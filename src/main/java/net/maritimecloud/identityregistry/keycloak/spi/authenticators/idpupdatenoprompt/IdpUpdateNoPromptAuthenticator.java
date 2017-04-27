/* Copyright 2017 Danish Maritime Authority.
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
            log.info(realm.isRegistrationEmailAsUsername() ? "Email" : "Username");
            context.getClientSession().setNote(ENFORCE_UPDATE_PROFILE, "true");
            context.resetFlow();
            return;
        }

        // If the cert2oidc client is used, the certificate IDP must be used as well
        String cert2oidcClientName = "cert2oidc";
        String certificateIdpName = "certificates";
        String idpName = brokerContext.getIdpConfig().getAlias();
        String clientName = brokerContext.getClientSession().getClient().getClientId();
        log.infof("Coming from client '%s', using IDP '%s'.", clientName, idpName);
        if (clientName.toLowerCase().equals(cert2oidcClientName) && !idpName.toLowerCase().equals(certificateIdpName)) {
            throw new AuthenticationFlowException("This client requires a certificate!", AuthenticationFlowError.INVALID_CLIENT_SESSION);
        }
        // Delete any duplicate user that shares email or username with the user logging in.
        deleteDuplicateUser(username, context, brokerContext);

        log.infof("Creating account for user '%s' and linking with identity provider '%s'.", username, idpName);
        UserModel brokeredUser = session.users().addUser(realm, username);
        brokeredUser.setEnabled(true);
        brokeredUser.setEmail(brokerContext.getEmail());
        brokeredUser.setFirstName(brokerContext.getFirstName());
        brokeredUser.setLastName(brokerContext.getLastName());
        // Copy attributes
        for (Map.Entry<String, List<String>> attr : serializedCtx.getAttributes().entrySet()) {
            brokeredUser.setAttribute(attr.getKey(), attr.getValue());
        }
        context.setUser(brokeredUser);
        context.getClientSession().setNote(BROKER_REGISTERED_NEW_USER, "true");
        context.success();

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

    private void deleteDuplicateUser(String username, AuthenticationFlowContext context, BrokeredIdentityContext brokerContext) {
        String email = brokerContext.getEmail();
        if (email != null && !email.isEmpty()) {
            UserModel userWithEmail = context.getSession().users().getUserByEmail(email, context.getRealm());
            if (userWithEmail != null) {
                // Found an existing user with the same email - delete it!
                log.info("Found an existing user with the same email - delete it!");
                context.getSession().users().removeUser(context.getRealm(), userWithEmail);
            } else {
                log.info("Did not find any conflicting users.");
            }
        } else {
            log.info("The user has no email - so no conflict...");
        }
        UserModel existingUser = context.getSession().users().getUserByUsername(username, context.getRealm());
        if (existingUser != null) {
            // Found an existing user with the same username - delete it!
            log.info("Found an existing user with the same username - delete it!");
            context.getSession().users().removeUser(context.getRealm(), existingUser);
        }
    }

}
