/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 */

package at.bitfire.davdroid.network

import android.util.Base64
import at.bitfire.davdroid.ui.setup.LoginInfo
import io.ktor.http.Url
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import net.openid.appauth.AuthState
import net.openid.appauth.AuthorizationRequest
import net.openid.appauth.ResponseTypeValues
import java.net.URI
import java.util.logging.Logger
import javax.inject.Inject

/**
 * Sign-in with the identity provider of an arbitrary CalDAV/CardDAV server (OAuth 2.0 / OpenID Connect),
 * without the user having to know anything but the server (or their email address) and their credentials:
 *
 * 1. Which authorization server: from a [LoginInfo.OidcHint] (e.g. a connection profile), or discovered
 *    via the DAV server's protected resource metadata ([OAuthDiscovery]).
 * 2. Which client ID, in this order:
 *    - given by the hint (the server's operator registered DAVx⁵ at their identity provider),
 *    - registered with an initial access token from the hint (the server handed out a one-time token),
 *    - registered openly (RFC 7591), as draft-ietf-mailmaint-oauth-public expects of servers.
 * 3. Authorization code flow with PKCE (S256, added by AppAuth) in the browser. Refresh tokens
 *    keep the account signed in; `offline_access` is requested when the server supports it.
 */
class OAuthOidc @Inject constructor(
    private val discovery: OAuthDiscovery,
    private val registration: OAuthRegistration,
    private val oAuthIntegration: OAuthIntegration,
    private val logger: Logger
) {

    class OidcException(message: String, cause: Throwable? = null) : Exception(message, cause)

    /** A prepared sign-in: the request to open in the browser, and the DAV URL to continue with. */
    data class Prepared(
        val request: AuthorizationRequest,
        val baseUri: URI,
        val loginHint: String?
    )

    /**
     * Prepares the sign-in for [serverUrlOrEmail].
     *
     * @throws OidcException if the server announces no identity provider, or no client ID can be obtained
     */
    suspend fun prepare(serverUrlOrEmail: String, hint: LoginInfo.OidcHint?, locale: String?): Prepared {
        val input = serverUrlOrEmail.trim()
        val loginHint = hint?.loginHint ?: input.takeIf { it.contains("@") && !it.contains("://") }

        // 1. authorization server
        val candidates = discovery.candidateUrls(input)
        val resource = if (hint?.issuer == null) discovery.findProtectedResource(candidates) else null
        val issuer = hint?.issuer?.let { Url(it) }
            ?: resource?.authorizationServers?.firstOrNull()
            ?: throw OidcException("The server doesn't announce an identity provider for signing in.")
        val server = discovery.authorizationServer(issuer)
        if (server.codeChallengeMethodsSupported.isNotEmpty() && "S256" !in server.codeChallengeMethodsSupported)
            throw OidcException("The identity provider doesn't support PKCE (S256).")

        // scopes: given, or what the server needs (openid + email to know the account, offline_access to stay signed in)
        val scope = hint?.scope ?: defaultScope(resource?.scopesSupported.orEmpty(), server.scopesSupported)

        // 2. client ID
        val clientId = hint?.clientId ?: run {
            val endpoint = server.registrationEndpoint
                ?: throw OidcException("The identity provider doesn't let apps register, and the server named no client ID.")
            registration.register(endpoint, scope, hint?.registrationToken)
        }
        logger.info("OIDC sign-in at ${server.issuer} as client $clientId, scope \"$scope\"")

        // 3. authorization request
        val request = AuthorizationRequest.Builder(
            server.toServiceConfiguration(),
            clientId,
            ResponseTypeValues.CODE,
            oAuthIntegration.redirectUri
        )
            .setScope(scope)
            .setLoginHint(loginHint)
            .setUiLocales(locale)
            .build()

        val baseUri = resource?.resource?.toString()?.let { URI(it) }
            ?: URI(candidates.first().toString())
        return Prepared(request, baseUri, loginHint)
    }


    companion object {

        /**
         * `openid email offline_access` as far as the servers support them — everything if they don't say.
         */
        fun defaultScope(resourceScopes: List<String>, serverScopes: List<String>): String {
            val wanted = listOf("openid", "email", "offline_access")
            val supported = resourceScopes.ifEmpty { serverScopes }
            return (if (supported.isEmpty()) wanted else wanted.filter { it in supported } + resourceScopes.filter { it !in wanted })
                .distinct()
                .joinToString(" ")
        }

        /**
         * The email address in the ID token of [authState], for the account name. The token came from the
         * token endpoint over TLS, so its claims are used without verifying the signature (the account name
         * is a label, nothing is authorized by it).
         */
        fun emailFromIdToken(authState: AuthState): String? = try {
            authState.idToken?.split('.')?.getOrNull(1)?.let { payload ->
                val claims = Json.parseToJsonElement(String(Base64.decode(payload, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)))
                claims.jsonObject["email"]?.jsonPrimitive?.content
            }
        } catch (_: Exception) {
            null
        }

    }

}
