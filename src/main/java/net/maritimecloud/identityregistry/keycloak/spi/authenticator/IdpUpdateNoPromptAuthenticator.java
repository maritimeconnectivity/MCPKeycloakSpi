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
package net.maritimecloud.identityregistry.keycloak.spi.authenticator;

import java.util.List;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import net.maritimecloud.identityregistry.keycloak.spi.authenticator.util.ExistingUserInfo;
import net.maritimecloud.identityregistry.keycloak.spi.authenticator.util.SerializedBrokeredIdentityContext;

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

        String username = getUsername(context, serializedCtx, brokerContext);
        if (username == null) {
            log.debug(realm.isRegistrationEmailAsUsername() ? "Email" : "Username");
            context.getClientSession().setNote(ENFORCE_UPDATE_PROFILE, "true");
            context.resetFlow();
            return;
        }

        UserModel existingUser = context.getSession().users().getUserByUsername(username, context.getRealm());

        if (existingUser == null) {
            log.debugf("No duplication detected. Creating account for user '%s' and linking with identity provider '%s' .",
                    username, brokerContext.getIdpConfig().getAlias());

            UserModel federatedUser = session.users().addUser(realm, username);
            federatedUser.setEnabled(true);
            federatedUser.setEmail(brokerContext.getEmail());
            federatedUser.setFirstName(brokerContext.getFirstName());
            federatedUser.setLastName(brokerContext.getLastName());

            for (Map.Entry<String, List<String>> attr : serializedCtx.getAttributes().entrySet()) {
                federatedUser.setAttribute(attr.getKey(), attr.getValue());
            }

            context.setUser(federatedUser);
            context.getClientSession().setNote(BROKER_REGISTERED_NEW_USER, "true");
            context.success();
        } else {
            log.debugf("Duplication detected. There is already existing user with %s '%s' .",
                    UserModel.USERNAME, existingUser.getUsername());

            existingUser.setEmail(brokerContext.getEmail());
            existingUser.setFirstName(brokerContext.getFirstName());
            existingUser.setLastName(brokerContext.getLastName());
            // Clear existing attributes
            for (Map.Entry<String, List<String>> attr : existingUser.getAttributes().entrySet()) {
                existingUser.removeAttribute(attr.getKey());
            }
            // Insert new attribute values
            for (Map.Entry<String, List<String>> attr : serializedCtx.getAttributes().entrySet()) {
                existingUser.setAttribute(attr.getKey(), attr.getValue());
            }

            context.setUser(existingUser);
            //context.getClientSession().setNote(BROKER_REGISTERED_NEW_USER, "true");
            context.success();
        }
    }

    protected String getUsername(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {
        RealmModel realm = context.getRealm();
        return realm.isRegistrationEmailAsUsername() ? brokerContext.getEmail() : brokerContext.getModelUsername();
    }

    // Could be overriden to detect duplication based on other criterias (firstName, lastName, ...)
    protected ExistingUserInfo checkExistingUser(AuthenticationFlowContext context, String username, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {

        /*if (brokerContext.getEmail() != null) {
            UserModel existingUser = context.getSession().users().getUserByEmail(brokerContext.getEmail(), context.getRealm());
            if (existingUser != null) {
                return new ExistingUserInfo(existingUser.getId(), UserModel.EMAIL, existingUser.getEmail());
            }
        }*/

        UserModel existingUser = context.getSession().users().getUserByUsername(username, context.getRealm());
        if (existingUser != null) {
            return new ExistingUserInfo(existingUser.getId(), UserModel.USERNAME, existingUser.getUsername());
        }

        return null;
    }
    @Override
    protected void actionImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx,
            BrokeredIdentityContext brokerContext) {
        // TODO Auto-generated method stub
        
    }


}
