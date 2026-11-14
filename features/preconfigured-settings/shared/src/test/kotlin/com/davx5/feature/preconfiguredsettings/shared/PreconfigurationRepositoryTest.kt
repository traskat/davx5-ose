/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 */

package com.davx5.feature.preconfiguredsettings.shared

import at.bitfire.davdroid.network.HttpClientBuilder
import com.davx5.feature.preconfiguredsettings.shared.PreconfiguredSettings.BasicAuthCredentials
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpStatusCode
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.intellij.lang.annotations.Language
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import kotlin.test.assertFailsWith

@RunWith(RobolectricTestRunner::class)
class PreconfigurationRepositoryTest {

    private val httpClientBuilder: HttpClientBuilder = mockk()
    private val preconfigurationRepository = PreconfigurationRepository(httpClientBuilder)

    @Test
    fun testFetchPreconfiguredSettings() = runTest {
        @Language("json")
        val json =
            """
            {
              "baseRoot": "https://davx5.com",
              "basicAuth": {
                "username": "username",
                "password": "password"
              },
              "someUnknownProperty": "should-be-ignored"
            }
            """.trimIndent()
        respondWith(HttpStatusCode.OK, json)

        val settings = preconfigurationRepository.fetchPreconfiguredSettings("https://example.com/")

        assertEquals("https://davx5.com", settings.baseRoot)
        assertEquals(BasicAuthCredentials("username", "password"), settings.basicAuth)
    }

    @Test
    fun testFetchPreconfiguredSettings_oauth() = runTest {
        @Language("json")
        val json =
            """
            {
              "baseRoot": "https://dav.example.com/",
              "oauth": {
                "issuer": "https://idp.example.com/realms/acme",
                "client_id": "davx5",
                "scope": "openid email offline_access",
                "login_hint": "user@example.com"
              }
            }
            """.trimIndent()
        respondWith(HttpStatusCode.OK, json)

        val settings = preconfigurationRepository.fetchPreconfiguredSettings("https://example.com/")
        val loginInfo = settings.toLoginInfo("https://example.com/")

        assertEquals(null, loginInfo.credentials)
        assertEquals("user@example.com", loginInfo.suggestedAccountName)
        val hint = loginInfo.oidc!!
        assertEquals("https://idp.example.com/realms/acme", hint.issuer)
        assertEquals("davx5", hint.clientId)
        assertEquals("openid email offline_access", hint.scope)
        assertEquals("user@example.com", hint.loginHint)
    }

    @Test
    fun testFetchPreconfiguredSettings_oauthRegistrationToken() = runTest {
        respondWith(HttpStatusCode.OK, """{"baseRoot":"https://dav.example.com/","oauth":{"registration_token":"one-time"}}""")
        val loginInfo = preconfigurationRepository.fetchPreconfiguredSettings("https://example.com/").toLoginInfo("https://example.com/")
        assertEquals("one-time", loginInfo.oidc!!.registrationToken)
        assertEquals(null, loginInfo.oidc!!.issuer)
    }

    @Test
    fun testFetchPreconfiguredSettings_basicAuthWinsOverOauth() = runTest {
        respondWith(HttpStatusCode.OK, """{"baseRoot":"https://dav.example.com/","basicAuth":{"username":"u","password":"p"},"oauth":{"client_id":"x"}}""")
        val loginInfo = preconfigurationRepository.fetchPreconfiguredSettings("https://example.com/").toLoginInfo("https://example.com/")
        assertEquals(null, loginInfo.oidc)
        assertEquals("u", loginInfo.credentials!!.username)
    }

    @Test
    fun testFetchPreconfiguredSettings_badServer() = runTest {
        respondWith(HttpStatusCode.NotFound, "not found")

        assertFailsWith<InvalidPreconfiguredSettingsException> {
            preconfigurationRepository.fetchPreconfiguredSettings("https://example.com/")
        }
    }

    @Test
    fun testFetchPreconfiguredSettings_badResponse() = runTest {
        respondWith(HttpStatusCode.OK, "invalid")

        assertFailsWith<InvalidPreconfiguredSettingsException> {
            preconfigurationRepository.fetchPreconfiguredSettings("https://example.com/")
        }
    }

    private fun respondWith(status: HttpStatusCode, body: String) {
        every { httpClientBuilder.build() } answers {
            HttpClient(MockEngine { respond(body, status) })
        }
    }
}
