/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 */

package at.bitfire.davdroid.ui.setup

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import at.bitfire.davdroid.R
import at.bitfire.davdroid.network.OAuthIntegration
import at.bitfire.davdroid.network.OAuthOidc
import at.bitfire.davdroid.network.OAuthRegistration
import at.bitfire.davdroid.settings.Credentials
import dagger.assisted.Assisted
import dagger.assisted.AssistedFactory
import dagger.assisted.AssistedInject
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.launch
import net.openid.appauth.AuthorizationRequest
import net.openid.appauth.AuthorizationResponse
import net.openid.appauth.AuthorizationService
import java.util.Locale
import java.util.logging.Level
import java.util.logging.Logger

@HiltViewModel(assistedFactory = OidcLoginViewModel.Factory::class)
class OidcLoginViewModel @AssistedInject constructor(
    @Assisted val initialLoginInfo: LoginInfo,
    private val authService: AuthorizationService,
    @ApplicationContext val context: Context,
    private val logger: Logger,
    private val oAuthOidc: OAuthOidc,
    private val oAuthIntegration: OAuthIntegration
) : ViewModel() {

    @AssistedFactory
    interface Factory {
        fun create(loginInfo: LoginInfo): OidcLoginViewModel
    }

    override fun onCleared() {
        authService.dispose()
    }

    data class UiState(
        /** server URL or email address */
        val server: String = "",
        val inProgress: Boolean = false,
        val error: String? = null,

        /** request to open in the browser (set when prepared) */
        val authorizationRequest: AuthorizationRequest? = null,
        /** login info (set after successful login) */
        val result: LoginInfo? = null
    ) {
        val canContinue = !inProgress && server.isNotBlank()
    }

    var uiState by mutableStateOf(UiState())
        private set

    /** Set while the browser is open: where to continue afterwards. */
    private var pending: OAuthOidc.Prepared? = null

    /** Whether the sign-in starts by itself (the server said how to sign in, e.g. in a connection profile). */
    val autoStart = initialLoginInfo.oidc != null && initialLoginInfo.baseUri != null

    init {
        uiState = UiState(
            server = initialLoginInfo.baseUri?.toString()
                ?: initialLoginInfo.oidc?.loginHint
                ?: initialLoginInfo.credentials?.username
                ?: ""
        )
    }

    fun setServer(server: String) {
        uiState = uiState.copy(server = server)
    }

    fun authorizationContract() = OAuthIntegration.AuthorizationContract(authService)

    fun signIn() {
        if (!uiState.canContinue)
            return
        uiState = uiState.copy(inProgress = true, error = null)
        viewModelScope.launch {
            try {
                val prepared = oAuthOidc.prepare(uiState.server, initialLoginInfo.oidc, Locale.getDefault().toLanguageTag())
                pending = prepared
                uiState = uiState.copy(inProgress = false, authorizationRequest = prepared.request)
            } catch (e: Exception) {
                logger.log(Level.WARNING, "OIDC sign-in couldn't be prepared", e)
                val message = when (e) {
                    is OAuthRegistration.RegistrationRefusedException -> context.getString(R.string.login_oidc_registration_refused)
                    is OAuthOidc.OidcException -> e.message
                    else -> null
                } ?: e.message ?: e.toString()
                uiState = uiState.copy(inProgress = false, error = message)
            }
        }
    }

    fun signInFailed() {
        uiState = uiState.copy(error = context.getString(R.string.install_browser))
    }

    fun authenticate(authResponse: AuthorizationResponse) {
        val prepared = pending ?: return
        uiState = uiState.copy(inProgress = true, error = null)
        viewModelScope.launch {
            try {
                val authState = oAuthIntegration.authenticate(authService, authResponse)
                val accountName = OAuthOidc.emailFromIdToken(authState) ?: prepared.loginHint
                uiState = uiState.copy(
                    inProgress = false,
                    result = LoginInfo(
                        baseUri = initialLoginInfo.baseUri ?: prepared.baseUri,
                        credentials = Credentials(authState = authState),
                        suggestedAccountName = accountName,
                        preconfigurationUrl = initialLoginInfo.preconfigurationUrl
                    )
                )
            } catch (e: Exception) {
                logger.log(Level.WARNING, "OIDC authentication failed", e)
                uiState = uiState.copy(inProgress = false, error = e.message ?: e.toString())
            }
        }
    }

    fun authCodeFailed() {
        uiState = uiState.copy(error = context.getString(R.string.login_oauth_couldnt_obtain_auth_code))
    }

    fun requestLaunched() {
        uiState = uiState.copy(authorizationRequest = null)
    }

    fun resetResult() {
        uiState = uiState.copy(result = null)
    }

}
