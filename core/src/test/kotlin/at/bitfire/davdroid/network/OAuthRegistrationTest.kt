/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 */

package at.bitfire.davdroid.network

import android.net.Uri
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.toByteArray
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Url
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class OAuthRegistrationTest {

    private val integration = mockk<OAuthIntegration> {
        every { redirectUri } returns Uri.parse("at.bitfire.davdroid:/oauth2/redirect")
    }
    private val registration = OAuthRegistration(mockk(relaxed = true), integration)

    private var sentBody: String? = null
    private var sentAuth: String? = null

    private fun serve(status: HttpStatusCode, body: String) {
        registration.clientFactory = {
            HttpClient(MockEngine { request ->
                sentBody = String(request.body.toByteArray())
                sentAuth = request.headers[HttpHeaders.Authorization]
                respond(body, status)
            })
        }
    }

    @Test
    fun `registers as a public native client`() = runTest {
        serve(HttpStatusCode.Created, """{"client_id":"abc-123","redirect_uris":["at.bitfire.davdroid:/oauth2/redirect"]}""")
        val id = registration.register(Url("https://idp.example/register"), "openid email offline_access")
        assertEquals("abc-123", id)
        assertNull("open registration sends no credential", sentAuth)

        val sent = Json.parseToJsonElement(sentBody!!).jsonObject
        assertEquals("none", sent["token_endpoint_auth_method"]!!.jsonPrimitive.content)
        assertEquals(listOf("authorization_code", "refresh_token"), sent["grant_types"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals(listOf("code"), sent["response_types"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals(listOf("at.bitfire.davdroid:/oauth2/redirect"), sent["redirect_uris"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals("openid email offline_access", sent["scope"]!!.jsonPrimitive.content)
        assertTrue("no secret is requested", !sent.containsKey("client_secret"))
    }

    @Test
    fun `uses an initial access token when given one`() = runTest {
        serve(HttpStatusCode.Created, """{"client_id":"xyz"}""")
        registration.register(Url("https://idp.example/register"), null, initialAccessToken = "one-time")
        assertEquals("Bearer one-time", sentAuth)
        assertTrue("scope left to the server", !Json.parseToJsonElement(sentBody!!).jsonObject.containsKey("scope"))
    }

    @Test
    fun `a refused registration is reported as refused`() = runTest {
        serve(HttpStatusCode.Forbidden, """{"error":"insufficient_scope"}""")
        assertTrue(runCatching { registration.register(Url("https://idp.example/register"), null) }.exceptionOrNull()
                is OAuthRegistration.RegistrationRefusedException)
    }

    @Test
    fun `another failure is a plain registration error`() = runTest {
        serve(HttpStatusCode.InternalServerError, "oops")
        val e = runCatching { registration.register(Url("https://idp.example/register"), null) }.exceptionOrNull()
        assertTrue(e is OAuthRegistration.RegistrationException && e !is OAuthRegistration.RegistrationRefusedException)
    }

}
