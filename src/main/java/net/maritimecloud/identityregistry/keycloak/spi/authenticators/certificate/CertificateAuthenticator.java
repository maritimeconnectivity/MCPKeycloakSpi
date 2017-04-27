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
package net.maritimecloud.identityregistry.keycloak.spi.authenticators.certificate;

import net.maritimecloud.pki.CertificateHandler;
import net.maritimecloud.pki.PKIIdentity;
import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class CertificateAuthenticator implements Authenticator {

    private static final Logger log = Logger.getLogger(CertificateAuthenticator.class);

    public CertificateAuthenticator() {
    }

    /**
     * Converts the certificate in the header to a Keycloak User.
     * It is assumed that the certificate is verified by the reserve proxy (nginx) infront of keycloak.
     *
     * @param authenticationFlowContext The context...
     */
    @Override
    public void authenticate(AuthenticationFlowContext authenticationFlowContext) {
        // Get the client certificate from the HTTP header
        HttpRequest req = authenticationFlowContext.getHttpRequest();
        List<String> certStrList = req.getHttpHeaders().getRequestHeader("X-Client-Certificate");
        if (certStrList.size() != 1) {
            log.warn("No client certificate detected!");
            throw new AuthenticationFlowException("No client certificate detected!", AuthenticationFlowError.INVALID_USER);
        }
        // Convert the header string to a certificate
        X509Certificate userCertificate = CertificateHandler.getCertFromNginxHeader(certStrList.get(0));
        if (userCertificate == null) {
            log.warn("Could not read client certificate!");
            throw new AuthenticationFlowException("Could not read client certificate!", AuthenticationFlowError.INVALID_USER);
        }

        // Get user details from the certificate
        PKIIdentity user = CertificateHandler.getIdentityFromCert(userCertificate);
        if (user == null) {
            log.warn("Extraction of data from the certificate failed!");
            throw new AuthenticationFlowException("Extraction of data from the certificate failed!", AuthenticationFlowError.INVALID_USER);
        }

        // Check for required data
        String mrn = user.getMrn();
        String fullname = user.getCn();
        String orgMrn = user.getO();
        String email = user.getEmail();
        if (fullname == null || fullname.isEmpty() || mrn == null || mrn.isEmpty() || orgMrn == null || orgMrn.isEmpty()) {
            log.warn("Required data is not available in client certificate!");
            throw new AuthenticationFlowException("Required data is not available in client certificate!", AuthenticationFlowError.INVALID_USER);
        }
        KeycloakSession session = authenticationFlowContext.getSession();
        RealmModel realm = authenticationFlowContext.getRealm();
        String permissions = user.getPermissions();

        // Try to find existing user
        UserModel existingUser = session.users().getUserByUsername(mrn, authenticationFlowContext.getRealm());
        if (existingUser == null) {
            log.infof("No duplication detected. Creating account for user '%s'.", mrn);

            UserModel federatedUser = session.users().addUser(realm, mrn);
            federatedUser.setEnabled(true);
            if (email != null && !email.trim().isEmpty()) {
                federatedUser.setEmail(email);
            }
            federatedUser.setFirstName(user.getFirstName());
            federatedUser.setLastName(user.getLastName());

            log.info("About to set permissions attr to: " + user.getPermissions());
            if (permissions != null && !permissions.trim().isEmpty()) {
                federatedUser.setAttribute("permissions", Arrays.asList(permissions));
                log.info("Just set permissions attr to: " + permissions);
            }
            log.info("About to set mrn attr to: " + mrn);
            if (mrn != null && !mrn.trim().isEmpty()) {
                federatedUser.setAttribute("mrn", Arrays.asList(mrn));
                log.info("Just set mrn attr to: " + mrn);
            }
            log.info("About to set org attr to: " + orgMrn);
            if (orgMrn != null && !orgMrn.trim().isEmpty()) {
                federatedUser.setAttribute("org", Arrays.asList(orgMrn));
                log.info("Just set org attr to: " + orgMrn);
            }

            authenticationFlowContext.setUser(federatedUser);
            //context.getClientSession().setNote(BROKER_REGISTERED_NEW_USER, "true");
            authenticationFlowContext.success();
        } else {
            log.infof("Existing user detected with %s '%s' .", UserModel.USERNAME, existingUser.getUsername());

            if (email != null && !email.trim().isEmpty()) {
                existingUser.setEmail(email);
            } else if (existingUser.getEmail() != null) {
                existingUser.setEmail(null);
            }
            existingUser.setFirstName(user.getFirstName());
            existingUser.setLastName(user.getLastName());

            // Clear existing attributes
            for (Map.Entry<String, List<String>> attr : existingUser.getAttributes().entrySet()) {
                existingUser.removeAttribute(attr.getKey());
            }
            log.info("About to set permissions attr to: " + permissions);
            if (permissions != null && !permissions.trim().isEmpty()) {
                existingUser.setAttribute("permissions", Arrays.asList(permissions));
                log.info("Just set permissions attr to: " + permissions);
            }
            log.info("About to set mrn attr to: " + mrn);
            if (mrn != null && !mrn.trim().isEmpty()) {
                existingUser.setAttribute("mrn", Arrays.asList(mrn));
                log.info("Just set mrn attr to: " + mrn);
            }
            log.info("About to set org attr to: " + orgMrn);
            if (orgMrn != null && !orgMrn.trim().isEmpty()) {
                existingUser.setAttribute("org", Arrays.asList(orgMrn));
                log.info("Just set org attr to: " + orgMrn);
            }

            authenticationFlowContext.setUser(existingUser);
            //context.getClientSession().setNote(BROKER_REGISTERED_NEW_USER, "true");
            authenticationFlowContext.success();
        }
        log.info("Authentication flow succesfully completed!");
    }

    @Override
    public void action(AuthenticationFlowContext authenticationFlowContext) {

    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        // All users for this realm is expected to use certificate authentication
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        // If configuredFor() always returns true, this shouldn't be called, so do nothing
    }

    @Override
    public void close() {

    }
}
