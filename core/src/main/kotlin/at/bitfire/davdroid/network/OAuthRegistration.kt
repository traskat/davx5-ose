/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 */

package at.bitfire.davdroid.network

import androidx.annotation.VisibleForTesting
import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.Url
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import javax.inject.Inject

/**
 * OAuth 2.0 Dynamic Client Registration ([RFC 7591](https://www.rfc-editor.org/rfc/rfc7591)) of DAVx⁵ as a
 * public client, as specified for open public clients by draft-ietf-mailmaint-oauth-public section 3.3:
 * no client secret, `token_endpoint_auth_method` "none", grant types "authorization_code" and
 * "refresh_token", and DAVx⁵'s private-use redirect URI.
 *
 * Registration is either open (no credential), or uses an initial access token (RFC 7591 section 3)
 * that the server handed to the user, for instance in a connection profile — then the authorization
 * server does not have to accept registrations from anyone.
 */
class OAuthRegistration @Inject constructor(
    private val httpClientBuilder: HttpClientBuilder,
    private val oAuthIntegration: OAuthIntegration
) {

    open class RegistrationException(message: String) : Exception(message)

    /** The authorization server doesn't let this client register (HTTP 401/403, e.g. no open registration). */
    class RegistrationRefusedException(message: String) : RegistrationException(message)

    @VisibleForTesting
    internal var clientFactory: () -> HttpClient = { httpClientBuilder.build() }

    // defaults are the registration (grant types, auth method …) and must be sent; null fields are left out
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true; explicitNulls = false }

    /**
     * Registers DAVx⁵ at [registrationEndpoint].
     *
     * @param scope               scopes to register for (space-separated), or `null` to leave it to the server
     * @param initialAccessToken  initial access token, if the server requires one
     * @return the client ID; the client MUST use it (and the values the server returned) from now on
     */
    suspend fun register(registrationEndpoint: Url, scope: String?, initialAccessToken: String? = null): String {
        val request = RegistrationRequestJson(
            redirectUris = listOf(oAuthIntegration.redirectUri.toString()),
            scope = scope
        )
        val body = clientFactory().use { client ->
            val response = client.post(registrationEndpoint) {
                contentType(ContentType.Application.Json)
                header(HttpHeaders.Accept, "application/json")
                if (initialAccessToken != null)
                    header(HttpHeaders.Authorization, "Bearer $initialAccessToken")
                setBody(json.encodeToString(request))
            }
            if (response.status.value == 401 || response.status.value == 403)
                throw RegistrationRefusedException("Client registration refused: HTTP ${response.status.value} ${response.bodyAsText().take(200)}")
            if (!response.status.isSuccess())
                throw RegistrationException("Client registration: HTTP ${response.status.value} ${response.bodyAsText().take(200)}")
            response.bodyAsText()
        }
        val answer = json.decodeFromString<RegistrationResponseJson>(body)
        if (answer.clientId.isBlank())
            throw RegistrationException("Client registration returned no client ID")
        return answer.clientId
    }

    @Serializable
    internal data class RegistrationRequestJson(
        @SerialName("client_name") val clientName: String = "DAVx⁵",
        @SerialName("redirect_uris") val redirectUris: List<String>,
        @SerialName("grant_types") val grantTypes: List<String> = listOf("authorization_code", "refresh_token"),
        @SerialName("response_types") val responseTypes: List<String> = listOf("code"),
        @SerialName("token_endpoint_auth_method") val tokenEndpointAuthMethod: String = "none",
        @SerialName("application_type") val applicationType: String = "native",
        @SerialName("client_uri") val clientUri: String = "https://www.davx5.com",
        @SerialName("software_id") val softwareId: String = "at.bitfire.davdroid",
        val scope: String? = null
    )

    @Serializable
    private data class RegistrationResponseJson(
        @SerialName("client_id") val clientId: String = ""
    )

}
