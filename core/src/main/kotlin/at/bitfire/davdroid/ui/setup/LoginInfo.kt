/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 */

package at.bitfire.davdroid.ui.setup

import at.bitfire.davdroid.settings.Credentials
import at.bitfire.synctools.vcard.GroupMethod
import java.net.URI

data class LoginInfo(
    val baseUri: URI? = null,
    val credentials: Credentials? = null,

    val suggestedAccountName: String? = null,

    /** group method that should be pre-selected */
    val suggestedGroupMethod: GroupMethod = GroupMethod.GROUP_VCARDS,

    /** The URL that was used for fetching the configuration, if any */
    val preconfigurationUrl: String? = null,

    /**
     * Set when the user shall sign in with OpenID Connect / OAuth at the server's identity provider
     * (for instance because a connection profile says so) instead of with a password.
     */
    val oidc: OidcHint? = null
) {

    /**
     * What the server told about signing in with its identity provider, for instance in a
     * connection profile. Every field is optional; missing values are discovered.
     *
     * @param issuer             issuer of the authorization server
     * @param clientId           client ID to use (skips client registration)
     * @param registrationToken  initial access token for client registration (RFC 7591 section 3)
     * @param scope              scopes to request (space-separated)
     * @param loginHint          login hint for the authorization server (usually the email address)
     */
    data class OidcHint(
        val issuer: String? = null,
        val clientId: String? = null,
        val registrationToken: String? = null,
        val scope: String? = null,
        val loginHint: String? = null
    )

}