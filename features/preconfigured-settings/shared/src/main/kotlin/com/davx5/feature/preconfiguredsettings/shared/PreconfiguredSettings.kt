/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 */

package com.davx5.feature.preconfiguredsettings.shared

import at.bitfire.davdroid.settings.Credentials
import at.bitfire.davdroid.ui.setup.LoginInfo
import at.bitfire.davdroid.util.DavUtils.toURIorNull
import at.bitfire.synctools.util.SensitiveString.Companion.toSensitiveString
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Represents preconfigured settings for establishing a connection to a CalDAV/CardDAV server.
 *
 * This class holds the necessary configuration details such as the base root
 * URI and either basic authentication credentials or, with [oauth], how to sign in with the
 * server's identity provider (OpenID Connect / OAuth 2.0) instead of a password.
 */
@Serializable
data class PreconfiguredSettings(
    val baseRoot: String? = null,
    val basicAuth: BasicAuthCredentials? = null,
    val oauth: OAuthSettings? = null,
) {
    /**
     * Obtains an instance of [LoginInfo] from the data of the preconfigured settings.
     * @throws IllegalStateException if [baseRoot] is `null` or invalid.
     */
    fun toLoginInfo(preconfigurationUrl: String): LoginInfo {
        checkNotNull(baseRoot) { "baseRoot cannot be null." }
        val baseRootURI = baseRoot.toURIorNull()
        checkNotNull(baseRootURI) { "baseRoot is not a valid URI." }

        return LoginInfo(
            baseUri = baseRootURI,
            credentials = basicAuth?.toCredentials(),
            suggestedAccountName = basicAuth?.username ?: oauth?.loginHint,
            preconfigurationUrl = preconfigurationUrl,
            oidc = if (basicAuth == null) oauth?.toOidcHint() else null
        )
    }

    /**
     * Sign-in with the server's identity provider. Names follow the OAuth/OIDC parameters.
     *
     * - [issuer]: the authorization server; if missing, it is discovered from the server (RFC 9728).
     * - [clientId]: a client ID the server's operator registered for DAVx⁵ — no client registration needed.
     * - [registrationToken]: an initial access token for registering DAVx⁵ (RFC 7591 section 3), for
     *   identity providers that don't accept registrations from anyone.
     * - [scope], [loginHint]: what to request, and whom to suggest on the login page.
     */
    @Serializable
    data class OAuthSettings(
        val issuer: String? = null,
        @SerialName("client_id") val clientId: String? = null,
        @SerialName("registration_token") private val registrationToken: String? = null,
        val scope: String? = null,
        @SerialName("login_hint") val loginHint: String? = null
    ) {
        fun toOidcHint() = LoginInfo.OidcHint(
            issuer = issuer,
            clientId = clientId,
            registrationToken = registrationToken,
            scope = scope,
            loginHint = loginHint
        )

        override fun toString() =
            "OAuthSettings[issuer=$issuer, clientId=$clientId, registrationToken=${registrationToken?.let { "***" }}, scope=$scope]"
    }

    @Serializable
    data class BasicAuthCredentials(val username: String, private val password: String? = null) {
        fun toCredentials(): Credentials = Credentials(username, password?.toSensitiveString())

        override fun toString(): String {
            return "BasicAuthCredentials[username=$username, password=${password?.let { "***" } ?: "null"}]"
        }
    }
}
