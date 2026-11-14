/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 */

package at.bitfire.davdroid.network

import android.net.Uri
import at.bitfire.davdroid.ui.setup.LoginInfo
import io.ktor.http.Url
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.util.logging.Logger

@RunWith(RobolectricTestRunner::class)
class OAuthOidcTest {

    private val issuer = "https://idp.example.com/realms/acme"
    private val server = OAuthDiscovery.AuthorizationServer(
        issuer = issuer,
        authorizationEndpoint = Url("$issuer/auth"),
        tokenEndpoint = Url("$issuer/token"),
        registrationEndpoint = Url("$issuer/register"),
        scopesSupported = listOf("openid", "email", "offline_access", "profile"),
        codeChallengeMethodsSupported = listOf("S256")
    )

    private val discovery = mockk<OAuthDiscovery> {
        coEvery { candidateUrls(any()) } returns listOf(Url("https://dav.example.com/"))
        coEvery { findProtectedResource(any()) } returns OAuthDiscovery.ProtectedResource(
            resource = Url("https://dav.example.com/dav/"),
            authorizationServers = listOf(Url(issuer)),
            scopesSupported = listOf("openid", "email", "offline_access")
        )
        coEvery { authorizationServer(Url(issuer)) } returns server
    }
    private val registration = mockk<OAuthRegistration> {
        coEvery { register(any(), any(), any()) } returns "registered-id"
    }
    private val integration = mockk<OAuthIntegration> {
        every { redirectUri } returns Uri.parse("at.bitfire.davdroid:/oauth2/redirect")
    }
    private val oidc = OAuthOidc(discovery, registration, integration, Logger.getLogger("test"))

    @Test
    fun `discovered server, open registration`() = runTest {
        val p = oidc.prepare("dav.example.com", null, "de")
        assertEquals("registered-id", p.request.clientId)
        assertEquals("openid email offline_access", p.request.scope)
        assertEquals("S256", p.request.codeVerifierChallengeMethod)
        assertEquals("https://dav.example.com/dav/", p.baseUri.toString())
        coVerify { registration.register(Url("$issuer/register"), "openid email offline_access", null) }
    }

    @Test
    fun `client ID from the server skips registration and discovery`() = runTest {
        val p = oidc.prepare("https://dav.example.com/", LoginInfo.OidcHint(issuer = issuer, clientId = "davx5", loginHint = "a@example.com"), null)
        assertEquals("davx5", p.request.clientId)
        assertEquals("a@example.com", p.request.loginHint)
        coVerify(exactly = 0) { registration.register(any(), any(), any()) }
        coVerify(exactly = 0) { discovery.findProtectedResource(any()) }
    }

    @Test
    fun `registration token from the server is used for registration`() = runTest {
        oidc.prepare("https://dav.example.com/", LoginInfo.OidcHint(issuer = issuer, registrationToken = "one-time"), null)
        coVerify { registration.register(Url("$issuer/register"), any(), "one-time") }
    }

    @Test
    fun `email address is the login hint`() = runTest {
        assertEquals("user@example.com", oidc.prepare("user@example.com", null, null).request.loginHint)
    }

    @Test
    fun `no identity provider announced`() = runTest {
        coEvery { discovery.findProtectedResource(any()) } returns null
        assertTrue(runCatching { oidc.prepare("dav.example.com", null, null) }.exceptionOrNull() is OAuthOidc.OidcException)
    }

    @Test
    fun `no registration endpoint and no client ID`() = runTest {
        coEvery { discovery.authorizationServer(any()) } returns server.copy(registrationEndpoint = null)
        assertTrue(runCatching { oidc.prepare("dav.example.com", null, null) }.exceptionOrNull() is OAuthOidc.OidcException)
    }

    @Test
    fun `defaultScope keeps what the resource asks for`() {
        assertEquals("openid email offline_access", OAuthOidc.defaultScope(emptyList(), emptyList()))
        assertEquals("openid email", OAuthOidc.defaultScope(emptyList(), listOf("openid", "email", "profile")))
        assertEquals("openid email offline_access dav", OAuthOidc.defaultScope(listOf("openid", "email", "offline_access", "dav"), emptyList()))
    }

}
