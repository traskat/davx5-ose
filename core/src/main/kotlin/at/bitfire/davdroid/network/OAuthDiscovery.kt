/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 */

package at.bitfire.davdroid.network

import androidx.annotation.VisibleForTesting
import androidx.core.net.toUri
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.client.statement.request
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.URLBuilder
import io.ktor.http.Url
import io.ktor.http.encodedPath
import io.ktor.http.isSuccess
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.openid.appauth.AuthorizationServiceConfiguration
import org.xbill.DNS.Type
import java.util.logging.Logger
import javax.inject.Inject

/**
 * Finds the OAuth 2.0 authorization server of an arbitrary CalDAV/CardDAV server, as described in
 * [draft-ietf-mailmaint-oauth-public](https://datatracker.ietf.org/doc/draft-ietf-mailmaint-oauth-public/)
 * ("OAuth Profile for Open Public Clients"), section 1.3 and 3.2:
 *
 * 1. An unauthenticated request to the DAV server is answered with `401` and a
 *    `WWW-Authenticate: Bearer resource_metadata="…"` challenge.
 * 2. That URL serves OAuth 2.0 Protected Resource Metadata ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)),
 *    which names the authorization server(s). Its `resource` must be the URL that was requested.
 * 3. The authorization server's metadata is read from the RFC 8414 location, or else from the
 *    OpenID Connect discovery location, and its `issuer` must match exactly.
 *
 * Nothing here is specific to an identity provider.
 */
class OAuthDiscovery @Inject constructor(
    private val httpClientBuilder: HttpClientBuilder,
    private val dnsRecordResolver: DnsRecordResolver,
    private val logger: Logger
) {

    /** Protected resource metadata (RFC 9728) of the DAV server. */
    data class ProtectedResource(
        val resource: Url,
        val authorizationServers: List<Url>,
        val scopesSupported: List<String>
    )

    /** Authorization server metadata (RFC 8414 / OpenID Connect discovery), as far as a public client needs it. */
    data class AuthorizationServer(
        val issuer: String,
        val authorizationEndpoint: Url,
        val tokenEndpoint: Url,
        val registrationEndpoint: Url?,
        val scopesSupported: List<String>,
        val codeChallengeMethodsSupported: List<String>
    ) {
        fun toServiceConfiguration() = AuthorizationServiceConfiguration(
            authorizationEndpoint.toString().toUri(),
            tokenEndpoint.toString().toUri(),
            registrationEndpoint?.toString()?.toUri()
        )
    }

    class DiscoveryException(message: String, cause: Throwable? = null) : Exception(message, cause)

    @VisibleForTesting
    internal var clientFactory: () -> HttpClient = {
        httpClientBuilder
            .followRedirects(true)
            .build()
    }

    @VisibleForTesting
    internal var noRedirectClientFactory: () -> HttpClient = {
        httpClientBuilder
            .followRedirects(false)
            .build()
    }

    private val json = Json { ignoreUnknownKeys = true }


    /**
     * URLs to probe for the `resource_metadata` challenge, for a server URL or an email address.
     *
     * - For a URL: the URL itself, then its well-known CalDAV and CardDAV locations (RFC 6764).
     * - For an email address: the CalDAV/CardDAV services the domain announces by SRV/TXT records
     *   (RFC 6764 section 3), then the well-known locations of the domain.
     */
    suspend fun candidateUrls(serverUrlOrEmail: String): List<Url> {
        val input = serverUrlOrEmail.trim()
        return if (input.contains("@") && !input.contains("://")) {
            val domain = input.substringAfterLast("@")
            buildList {
                for (service in listOf("caldav", "carddav")) {
                    val query = "_${service}s._tcp.$domain"
                    val srv = dnsRecordResolver.bestSRVRecord(dnsRecordResolver.resolve(query, Type.SRV))
                    if (srv != null) {
                        val host = srv.target.toString(true)
                        val paths = dnsRecordResolver.pathsFromTXTRecords(dnsRecordResolver.resolve(query, Type.TXT)) +
                                "/.well-known/$service"
                        for (path in paths)
                            add(URLBuilder("https://$host:${srv.port}").apply { encodedPath = path }.build())
                    }
                }
                add(Url("https://$domain/.well-known/caldav"))
                add(Url("https://$domain/.well-known/carddav"))
            }.distinct()
        } else {
            val base = Url(if (input.contains("://")) input else "https://$input")
            listOf(
                base,
                URLBuilder(base).apply { encodedPath = "/.well-known/caldav" }.build(),
                URLBuilder(base).apply { encodedPath = "/.well-known/carddav" }.build()
            ).distinct()
        }
    }

    /**
     * Probes [candidates] in order and returns the protected resource metadata announced by the first
     * one that answers with a `Bearer resource_metadata` challenge, or `null` if none does (the server
     * does not announce OAuth).
     */
    suspend fun findProtectedResource(candidates: List<Url>): ProtectedResource? {
        for (candidate in candidates) {
            val (requested, metadataUrl) = try {
                clientFactory().use { client ->
                    val response = client.get(candidate)
                    if (response.status != HttpStatusCode.Unauthorized)
                        return@use null
                    val url = resourceMetadataUrls(response.headers.getAll(HttpHeaders.WWWAuthenticate).orEmpty())
                        .firstOrNull() ?: return@use null
                    response.request.url to url
                } ?: continue
            } catch (e: Exception) {
                logger.fine("Couldn't probe $candidate for OAuth: $e")
                continue
            }
            return fetchProtectedResource(requested, metadataUrl)
        }
        return null
    }

    /**
     * Fetches protected resource metadata. Redirects are not followed (draft section 1.3), and the
     * metadata is only accepted if its `resource` is the URL that was requested (RFC 9728 section 3.3) —
     * otherwise any server could send the user to any authorization server in the name of another.
     */
    @VisibleForTesting
    internal suspend fun fetchProtectedResource(requested: Url, metadataUrl: String): ProtectedResource {
        val body = noRedirectClientFactory().use { client ->
            val response = client.get(metadataUrl) { header(HttpHeaders.Accept, "application/json") }
            if (!response.status.isSuccess())
                throw DiscoveryException("Protected resource metadata: HTTP ${response.status.value}")
            response.bodyAsText()
        }
        val metadata = try {
            json.decodeFromString<ResourceMetadataJson>(body)
        } catch (e: Exception) {
            throw DiscoveryException("Invalid protected resource metadata", e)
        }
        if (!sameUrl(metadata.resource, requested.toString()))
            throw DiscoveryException("Protected resource metadata is for ${metadata.resource}, not for $requested")
        val servers = metadata.authorizationServers.mapNotNull { runCatching { Url(it) }.getOrNull() }
        if (servers.isEmpty())
            throw DiscoveryException("Protected resource metadata names no authorization server")
        return ProtectedResource(Url(metadata.resource), servers, metadata.scopesSupported.orEmpty())
    }

    /**
     * Reads the metadata of the authorization server [issuer]: first from the RFC 8414 location
     * (well-known segment inserted after the host), then from the OpenID Connect discovery location.
     * The `issuer` in the document must be exactly [issuer] (RFC 8414 section 3.3).
     */
    suspend fun authorizationServer(issuer: Url): AuthorizationServer {
        val issuerString = issuer.toString().trimEnd('/')
        val path = issuer.encodedPath.trimEnd('/')
        val locations = listOf(
            URLBuilder(issuer).apply { encodedPath = "/.well-known/oauth-authorization-server$path" }.build(),
            URLBuilder(issuer).apply { encodedPath = "$path/.well-known/openid-configuration" }.build()
        )
        var lastError: Exception? = null
        for (location in locations) {
            val response: Pair<HttpResponse, String>? = try {
                clientFactory().use { client ->
                    val r = client.get(location) { header(HttpHeaders.Accept, "application/json") }
                    if (r.status.isSuccess()) r to r.bodyAsText() else null
                }
            } catch (e: Exception) {
                lastError = e
                null
            }
            val body = response?.second ?: continue
            val md = try {
                json.decodeFromString<ServerMetadataJson>(body)
            } catch (e: Exception) {
                lastError = DiscoveryException("Invalid authorization server metadata at $location", e)
                continue
            }
            if (md.issuer.trimEnd('/') != issuerString)
                throw DiscoveryException("Authorization server metadata at $location is for ${md.issuer}, not for $issuerString")
            return AuthorizationServer(
                issuer = md.issuer,
                authorizationEndpoint = Url(md.authorizationEndpoint),
                tokenEndpoint = Url(md.tokenEndpoint),
                registrationEndpoint = md.registrationEndpoint?.let { Url(it) },
                scopesSupported = md.scopesSupported.orEmpty(),
                codeChallengeMethodsSupported = md.codeChallengeMethodsSupported.orEmpty()
            )
        }
        throw DiscoveryException("No authorization server metadata found for $issuerString", lastError)
    }


    companion object {

        /**
         * Extracts the `resource_metadata` parameters of all `Bearer` challenges from `WWW-Authenticate`
         * header values (RFC 9110 section 11.6.1: a header may carry several challenges, and there may be
         * several headers).
         */
        fun resourceMetadataUrls(headerValues: List<String>): List<String> =
            headerValues.flatMap { parseChallenges(it) }
                .filter { it.scheme.equals("Bearer", ignoreCase = true) }
                .mapNotNull { it.params["resource_metadata"] }

        data class Challenge(val scheme: String, val params: Map<String, String>)

        /**
         * Parses a `WWW-Authenticate` value into challenges: `scheme [token68 | param=value *("," param=value)]`,
         * challenges separated by commas. Quoted values may contain commas and escaped quotes.
         */
        fun parseChallenges(value: String): List<Challenge> {
            val out = mutableListOf<Challenge>()
            var scheme: String? = null
            var params = mutableMapOf<String, String>()
            var i = 0
            val s = value

            fun skipSpaceAndCommas() {
                while (i < s.length && (s[i] == ' ' || s[i] == '\t' || s[i] == ',')) i++
            }
            fun readToken(): String {
                val start = i
                while (i < s.length && s[i] != ' ' && s[i] != '\t' && s[i] != ',' && s[i] != '=') i++
                return s.substring(start, i)
            }

            while (true) {
                skipSpaceAndCommas()
                if (i >= s.length) break
                val token = readToken()
                // whitespace before a possible "="
                var j = i
                while (j < s.length && (s[j] == ' ' || s[j] == '\t')) j++
                if (j < s.length && s[j] == '=' && scheme != null && !(j + 1 < s.length && s[j + 1] == '=' )) {
                    // auth-param
                    i = j + 1
                    while (i < s.length && (s[i] == ' ' || s[i] == '\t')) i++
                    val v = StringBuilder()
                    if (i < s.length && s[i] == '"') {
                        i++
                        while (i < s.length && s[i] != '"') {
                            if (s[i] == '\\' && i + 1 < s.length) i++
                            v.append(s[i]); i++
                        }
                        i++ // closing quote
                    } else {
                        while (i < s.length && s[i] != ',' && s[i] != ' ' && s[i] != '\t') { v.append(s[i]); i++ }
                    }
                    params[token.lowercase()] = v.toString()
                } else if (token.isNotEmpty()) {
                    if (scheme != null && params.isEmpty() && j < s.length && s[j] == '=') {
                        // token68 of the current scheme ("Negotiate abc=="): skip it
                        i = j
                        while (i < s.length && s[i] == '=') i++
                        continue
                    }
                    // a new challenge
                    scheme?.let { out += Challenge(it, params) }
                    scheme = token
                    params = mutableMapOf()
                }
            }
            scheme?.let { out += Challenge(it, params) }
            return out
        }

        /** Compares URLs as RFC 9728 requires "identical", tolerating only a trailing slash on the root. */
        fun sameUrl(a: String, b: String): Boolean {
            fun norm(u: String) = runCatching { Url(u) }.getOrNull()?.let {
                val path = it.encodedPath.ifEmpty { "/" }
                "${it.protocol.name}://${it.host.lowercase()}:${it.port}$path${if (it.encodedQuery.isNotEmpty()) "?" + it.encodedQuery else ""}"
            }
            return norm(a) != null && norm(a) == norm(b)
        }
    }

    @Serializable
    private data class ResourceMetadataJson(
        val resource: String,
        @SerialName("authorization_servers") val authorizationServers: List<String> = emptyList(),
        @SerialName("scopes_supported") val scopesSupported: List<String>? = null
    )

    @Serializable
    private data class ServerMetadataJson(
        val issuer: String,
        @SerialName("authorization_endpoint") val authorizationEndpoint: String,
        @SerialName("token_endpoint") val tokenEndpoint: String,
        @SerialName("registration_endpoint") val registrationEndpoint: String? = null,
        @SerialName("scopes_supported") val scopesSupported: List<String>? = null,
        @SerialName("code_challenge_methods_supported") val codeChallengeMethodsSupported: List<String>? = null
    )

}
