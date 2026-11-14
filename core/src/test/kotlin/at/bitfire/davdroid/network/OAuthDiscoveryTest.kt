/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 */

package at.bitfire.davdroid.network

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Url
import io.ktor.http.headersOf
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.logging.Logger

class OAuthDiscoveryTest {

    private val discovery = OAuthDiscovery(mockk(relaxed = true), mockk(relaxed = true), Logger.getLogger("test"))

    private fun serve(routes: Map<String, () -> Triple<HttpStatusCode, String, List<Pair<String, String>>>>) {
        val engine = MockEngine { request ->
            val route = routes[request.url.toString()]
                ?: return@MockEngine respond("", HttpStatusCode.NotFound)
            val (status, body, headers) = route()
            respond(body, status, headersOf(*headers.map { it.first to listOf(it.second) }.toTypedArray()))
        }
        discovery.clientFactory = { HttpClient(engine) }
        discovery.noRedirectClientFactory = { HttpClient(engine) { followRedirects = false } }
    }

    private val issuer = "https://idp.example.com/realms/acme"

    private val serverMetadata = """{
        "issuer": "$issuer",
        "authorization_endpoint": "$issuer/protocol/openid-connect/auth",
        "token_endpoint": "$issuer/protocol/openid-connect/token",
        "registration_endpoint": "$issuer/clients-registrations/openid-connect",
        "scopes_supported": ["openid", "email", "offline_access"],
        "code_challenge_methods_supported": ["S256"],
        "some_other_field": true
    }"""


    @Test
    fun `parseChallenges handles several challenges in one header`() {
        val challenges = OAuthDiscovery.parseChallenges(
            "Bearer realm=\"takt\", resource_metadata=\"https://dav.example.com/.well-known/oauth-protected-resource/dav/\", " +
                    "Basic realm=\"takt, the server\", charset=\"UTF-8\""
        )
        assertEquals(listOf("Bearer", "Basic"), challenges.map { it.scheme })
        assertEquals("https://dav.example.com/.well-known/oauth-protected-resource/dav/", challenges[0].params["resource_metadata"])
        assertEquals("takt, the server", challenges[1].params["realm"])
        assertEquals("UTF-8", challenges[1].params["charset"])
    }

    @Test
    fun `parseChallenges handles token68 and escaped quotes`() {
        val challenges = OAuthDiscovery.parseChallenges("Negotiate abc123==, Bearer error=\"invalid_token\", error_description=\"say \\\"hi\\\"\"")
        assertEquals(listOf("Negotiate", "Bearer"), challenges.map { it.scheme })
        assertEquals("say \"hi\"", challenges[1].params["error_description"])
    }

    @Test
    fun `resourceMetadataUrls only takes Bearer challenges, across headers`() {
        assertEquals(
            listOf("https://a.example/.well-known/oauth-protected-resource"),
            OAuthDiscovery.resourceMetadataUrls(listOf(
                "Basic realm=\"x\"",
                "bearer resource_metadata=\"https://a.example/.well-known/oauth-protected-resource\"",
                "Other resource_metadata=\"https://evil.example/\""
            ))
        )
    }

    @Test
    fun `findProtectedResource follows the challenge and checks the resource`() = runTest {
        val dav = "https://dav.example.com/dav/calendars/"
        val metadata = "https://dav.example.com/.well-known/oauth-protected-resource/dav/calendars/"
        serve(mapOf(
            "https://dav.example.com/" to { Triple(HttpStatusCode.OK, "<html/>", emptyList()) },
            "https://dav.example.com/.well-known/caldav" to { Triple(HttpStatusCode.MovedPermanently, "", listOf(HttpHeaders.Location to dav)) },
            dav to { Triple(HttpStatusCode.Unauthorized, "", listOf(
                HttpHeaders.WWWAuthenticate to "Bearer realm=\"takt\", resource_metadata=\"$metadata\", Basic realm=\"takt\""
            )) },
            metadata to { Triple(HttpStatusCode.OK, """{"resource":"$dav","authorization_servers":["$issuer"],"scopes_supported":["openid","email","offline_access"]}""",
                listOf(HttpHeaders.ContentType to "application/json")) }
        ))
        val pr = discovery.findProtectedResource(discovery.candidateUrls("https://dav.example.com/"))!!
        assertEquals(Url(issuer), pr.authorizationServers.first())
        assertEquals(listOf("openid", "email", "offline_access"), pr.scopesSupported)
    }

    @Test
    fun `metadata for another resource is refused`() = runTest {
        val dav = "https://dav.example.com/dav/"
        val metadata = "https://dav.example.com/.well-known/oauth-protected-resource/dav/"
        serve(mapOf(metadata to { Triple(HttpStatusCode.OK, """{"resource":"https://other.example/","authorization_servers":["$issuer"]}""", emptyList()) }))
        val e = runCatching { discovery.fetchProtectedResource(Url(dav), metadata) }.exceptionOrNull()
        assertTrue(e is OAuthDiscovery.DiscoveryException)
    }

    @Test
    fun `no challenge means no OAuth`() = runTest {
        serve(mapOf("https://dav.example.com/" to { Triple(HttpStatusCode.Unauthorized, "", listOf(HttpHeaders.WWWAuthenticate to "Basic realm=\"x\"")) }))
        assertNull(discovery.findProtectedResource(listOf(Url("https://dav.example.com/"))))
    }

    @Test
    fun `authorizationServer falls back from RFC 8414 to OpenID Connect discovery`() = runTest {
        serve(mapOf("$issuer/.well-known/openid-configuration" to { Triple(HttpStatusCode.OK, serverMetadata, emptyList()) }))
        val server = discovery.authorizationServer(Url(issuer))
        assertEquals(Url("$issuer/protocol/openid-connect/token"), server.tokenEndpoint)
        assertEquals(Url("$issuer/clients-registrations/openid-connect"), server.registrationEndpoint)
        assertEquals(listOf("S256"), server.codeChallengeMethodsSupported)
    }

    @Test
    fun `authorizationServer reads the RFC 8414 location first`() = runTest {
        serve(mapOf("https://idp.example.com/.well-known/oauth-authorization-server/realms/acme" to { Triple(HttpStatusCode.OK, serverMetadata, emptyList()) }))
        assertEquals(issuer, discovery.authorizationServer(Url(issuer)).issuer)
    }

    @Test
    fun `authorizationServer refuses metadata of another issuer`() = runTest {
        serve(mapOf("$issuer/.well-known/openid-configuration" to {
            Triple(HttpStatusCode.OK, serverMetadata.replace("\"issuer\": \"$issuer\"", "\"issuer\": \"https://evil.example\""), emptyList())
        }))
        assertTrue(runCatching { discovery.authorizationServer(Url(issuer)) }.exceptionOrNull() is OAuthDiscovery.DiscoveryException)
    }

    @Test
    fun `sameUrl tolerates only the root slash`() {
        assertTrue(OAuthDiscovery.sameUrl("https://a.example", "https://a.example/"))
        assertTrue(OAuthDiscovery.sameUrl("https://A.example:443/dav/", "https://a.example/dav/"))
        assertTrue(!OAuthDiscovery.sameUrl("https://a.example/dav", "https://a.example/dav/"))
        assertTrue(!OAuthDiscovery.sameUrl("https://a.example/", "http://a.example/"))
    }

}
