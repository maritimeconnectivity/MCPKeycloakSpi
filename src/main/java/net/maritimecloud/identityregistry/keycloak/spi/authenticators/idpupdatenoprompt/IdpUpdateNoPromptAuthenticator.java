/* Copyright 2016 Danish Maritime Authority.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package net.maritimecloud.identityregistry.keycloak.spi.authenticators.idpupdatenoprompt;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.*;

import net.maritimecloud.identityregistry.keycloak.spi.authenticators.idpupdatenoprompt.util.SerializedBrokeredIdentityContext;

/**
 * Authenticator that copies the user from a IDP into either a new user, or
 * updates an existing one with the same username. Does not prompt for review!
 * In part based on org.keycloak.authentication.authenticators.broker.IdpCreateUserIfUniqueAuthenticator
 */
public class IdpUpdateNoPromptAuthenticator extends AbstractIdpAuthenticator {

    private static final Logger log = Logger.getLogger(IdpUpdateNoPromptAuthenticator.class);

    @Override
    public boolean configuredFor(KeycloakSession arg0, RealmModel arg1, UserModel arg2) {
        return true;
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    protected void authenticateImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx,
            BrokeredIdentityContext brokerContext) {

        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();

        if (context.getClientSession().getNote(EXISTING_USER_INFO) != null) {
            context.attempted();
            return;
        }

        String username = getUsername(context, brokerContext);
        if (username == null) {
            log.debug(realm.isRegistrationEmailAsUsername() ? "Email" : "Username");
            context.getClientSession().setNote(ENFORCE_UPDATE_PROFILE, "true");
            context.resetFlow();
            return;
        }

        // If the cert2oidc client is used, the certificate IDP must be used as well
        String cert2oidcClientName = "cert2oidc";
        String certificateIdpName = "certificates";
        String idpName = brokerContext.getIdpConfig().getAlias();
        String clientName = brokerContext.getClientSession().getClient().getClientId();
        log.debugf("Coming from client '%s', using IDP '%s'.", clientName, idpName);
        if (clientName.toLowerCase().equals(cert2oidcClientName) && !idpName.toLowerCase().equals(certificateIdpName)) {
            throw new AuthenticationFlowException("This client requires a certificate!", AuthenticationFlowError.INVALID_CLIENT_SESSION);
        }

        UserModel existingUser = context.getSession().users().getUserByUsername(username, context.getRealm());
        deleteDuplicateUserEmail(existingUser, context, brokerContext);

        // TODO: Do some check to ensure that only the certificate IDP + one other IDP is linked to a user.

        if (existingUser == null) {
            log.debugf("No duplication detected. Creating account for user '%s' and linking with identity provider '%s'.",
                    username, idpName);

            UserModel brokeredUser = session.users().addUser(realm, username);
            brokeredUser.setEnabled(true);
            brokeredUser.setEmail(brokerContext.getEmail());
            brokeredUser.setFirstName(brokerContext.getFirstName());
            brokeredUser.setLastName(brokerContext.getLastName());

            for (Map.Entry<String, List<String>> attr : serializedCtx.getAttributes().entrySet()) {
                brokeredUser.setAttribute(attr.getKey(), attr.getValue());
            }

            // MRN and username is the same
            brokeredUser.setAttribute("mrn", Arrays.asList(username));
            context.setUser(brokeredUser);
            context.getClientSession().setNote(BROKER_REGISTERED_NEW_USER, "true");
            context.success();
        } else {
            log.debugf("Duplication detected. There is already existing user with %s '%s' .",
                    UserModel.USERNAME, existingUser.getUsername());

            existingUser.setEmail(brokerContext.getEmail());
            existingUser.setFirstName(brokerContext.getFirstName());
            existingUser.setLastName(brokerContext.getLastName());
            // Attribute updating is done in IdentityBrokerService
            context.setUser(existingUser);
            context.success();
        }
    }

    protected String getUsername(AuthenticationFlowContext context, BrokeredIdentityContext brokerContext) {
        RealmModel realm = context.getRealm();
        return realm.isRegistrationEmailAsUsername() ? brokerContext.getEmail() : brokerContext.getModelUsername();
    }

    @Override
    protected void actionImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx,
            BrokeredIdentityContext brokerContext) {
        // TODO Auto-generated method stub
    }

    private void deleteDuplicateUserEmail(UserModel existingUser, AuthenticationFlowContext context, BrokeredIdentityContext brokerContext) {
        String email = brokerContext.getEmail();
        if (email != null && !email.isEmpty()) {
            UserModel userWithEmail = context.getSession().users().getUserByEmail(email, context.getRealm());
            if (userWithEmail != null) {
                // Check if existingUser and the userWithEmail is the same
                if (existingUser != null && userWithEmail.getId().equals(existingUser.getId())) {
                    // All is good - continue to merge/link the users
                    log.debug("existingUser and the userWithEmail is the same - continue to merge/link the users.");
                    return;
                } else {
                    // Found an existing user with the same email - delete it!
                    log.debug("Found an existing user with the same email - delete it!");
                    context.getSession().users().removeUser(context.getRealm(), userWithEmail);
                }
            } else {
                log.debug("Did not find any conflicting users.");
            }
        } else {
            log.debug("The user has no email - so no conflict...");
        }
    }

}
