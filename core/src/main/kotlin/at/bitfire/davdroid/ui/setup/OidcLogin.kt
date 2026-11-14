/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 */

package at.bitfire.davdroid.ui.setup

import android.content.ActivityNotFoundException
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountCircle
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import at.bitfire.davdroid.R
import at.bitfire.davdroid.ui.composable.Assistant
import java.util.logging.Level
import java.util.logging.Logger

/**
 * Sign-in with the identity provider of the server (OpenID Connect / OAuth 2.0). The user enters the
 * server or their email address; everything else is discovered (see [at.bitfire.davdroid.network.OAuthOidc]).
 */
object OidcLogin : LoginType {

    override val title
        get() = R.string.login_type_oidc

    override val helpUrl: Uri?
        get() = null

    @Composable
    override fun LoginScreen(
        snackbarHostState: SnackbarHostState,
        initialLoginInfo: LoginInfo,
        onLogin: (LoginInfo) -> Unit
    ) {
        val model: OidcLoginViewModel = hiltViewModel(
            key = "oidc-" + initialLoginInfo.hashCode(),
            creationCallback = { factory: OidcLoginViewModel.Factory ->
                factory.create(loginInfo = initialLoginInfo)
            }
        )

        val authRequestContract = rememberLauncherForActivityResult(model.authorizationContract()) { authResponse ->
            if (authResponse != null)
                model.authenticate(authResponse)
            else
                model.authCodeFailed()
        }

        val uiState = model.uiState
        LaunchedEffect(uiState.authorizationRequest) {
            val request = uiState.authorizationRequest ?: return@LaunchedEffect
            model.requestLaunched()
            try {
                authRequestContract.launch(request)
            } catch (e: ActivityNotFoundException) {
                Logger.getGlobal().log(Level.WARNING, "Couldn't start OAuth intent", e)
                model.signInFailed()
            }
        }

        LaunchedEffect(uiState.result) {
            uiState.result?.let {
                onLogin(it)
                model.resetResult()
            }
        }

        LaunchedEffect(uiState.error) {
            uiState.error?.let { snackbarHostState.showSnackbar(it) }
        }

        // the server said how to sign in (connection profile): go to the identity provider at once
        LaunchedEffect(Unit) {
            if (model.autoStart)
                model.signIn()
        }

        OidcLoginScreen(
            server = uiState.server,
            onSetServer = model::setServer,
            inProgress = uiState.inProgress,
            canContinue = uiState.canContinue,
            onLogin = model::signIn
        )
    }

}

@Composable
fun OidcLoginScreen(
    server: String,
    onSetServer: (String) -> Unit = {},
    inProgress: Boolean,
    canContinue: Boolean,
    onLogin: () -> Unit = {}
) {
    val focusRequester = remember { FocusRequester() }

    Assistant(
        nextLabel = stringResource(R.string.login_login),
        nextEnabled = canContinue,
        onNext = onLogin
    ) {
        Column(
            Modifier
                .padding(8.dp)
                .verticalScroll(rememberScrollState())
        ) {
            Text(
                stringResource(R.string.login_type_oidc),
                style = MaterialTheme.typography.headlineMedium,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 8.dp)
            )
            Text(
                stringResource(R.string.login_oidc_info),
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp, bottom = 16.dp)
            )

            OutlinedTextField(
                value = server,
                onValueChange = onSetServer,
                label = { Text(stringResource(R.string.login_oidc_server)) },
                placeholder = { Text("dav.example.com / user@example.com") },
                singleLine = true,
                enabled = !inProgress,
                leadingIcon = { Icon(Icons.Default.AccountCircle, null) },
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Uri,
                    imeAction = ImeAction.Go
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .focusRequester(focusRequester)
            )

            if (inProgress)
                LinearProgressIndicator(Modifier.fillMaxWidth().padding(top = 8.dp))
        }
    }

    LaunchedEffect(Unit) {
        if (server.isEmpty())
            focusRequester.requestFocus()
    }
}

@Composable
@Preview(showBackground = true)
fun OidcLoginScreen_Preview() {
    OidcLoginScreen(
        server = "user@example.com",
        inProgress = false,
        canContinue = true
    )
}
