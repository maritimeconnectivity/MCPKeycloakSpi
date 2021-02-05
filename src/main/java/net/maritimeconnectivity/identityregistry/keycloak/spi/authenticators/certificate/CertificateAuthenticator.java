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
package net.maritimeconnectivity.identityregistry.keycloak.spi.authenticators.certificate;

import lombok.NoArgsConstructor;
import net.maritimeconnectivity.pki.CertificateHandler;
import net.maritimeconnectivity.pki.PKIIdentity;
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
import java.util.Collections;
import java.util.List;
import java.util.Map;

@NoArgsConstructor
public class CertificateAuthenticator implements Authenticator {

    private static final Logger log = Logger.getLogger(CertificateAuthenticator.class);

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
        UserModel existingUser = session.users().getUserByUsername(mrn, realm);
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
                federatedUser.setAttribute("permissions", Collections.singletonList(permissions));
                log.info("Just set permissions attr to: " + permissions);
            }
            log.info("About to set mrn attr to: " + mrn);
            if (!mrn.trim().isEmpty()) {
                federatedUser.setAttribute("mrn", Collections.singletonList(mrn));
                log.info("Just set mrn attr to: " + mrn);
            }
            log.info("About to set org attr to: " + orgMrn);
            if (!orgMrn.trim().isEmpty()) {
                federatedUser.setAttribute("org", Collections.singletonList(orgMrn));
                log.info("Just set org attr to: " + orgMrn);
            }
            extractNonUserAttributes(user, mrn, federatedUser);

            authenticationFlowContext.setUser(federatedUser);
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
                existingUser.setAttribute("permissions", Collections.singletonList(permissions));
                log.info("Just set permissions attr to: " + permissions);
            }
            log.info("About to set mrn attr to: " + mrn);
            if (!mrn.trim().isEmpty()) {
                existingUser.setAttribute("mrn", Collections.singletonList(mrn));
                log.info("Just set mrn attr to: " + mrn);
            }
            log.info("About to set org attr to: " + orgMrn);
            if (!orgMrn.trim().isEmpty()) {
                existingUser.setAttribute("org", Collections.singletonList(orgMrn));
                log.info("Just set org attr to: " + orgMrn);
            }
            extractNonUserAttributes(user, mrn, existingUser);

            authenticationFlowContext.setUser(existingUser);
        }
        authenticationFlowContext.success();
        log.info("Authentication flow successfully completed!");
    }

    private void extractNonUserAttributes(PKIIdentity user, String mrn, UserModel userModel) {
        if (!mrn.trim().contains(":user:")) {
            String flagState = user.getFlagState();
            String callSign = user.getCallSign();
            String imoNumber = user.getImoNumber();
            String mmsiNumber = user.getMmsiNumber();
            String aisShipType = user.getAisShipType();
            String portOfRegister = user.getPortOfRegister();
            String shipMrn = user.getShipMrn();
            String mrnSubsidiary = user.getMrnSubsidiary();
            String homeMmsUrl = user.getHomeMmsUrl();
            String url = user.getUrl();

            if (flagState != null && !flagState.trim().isEmpty()) {
                userModel.setAttribute("flagState", Collections.singletonList(flagState));
            }
            if (callSign != null && !callSign.trim().isEmpty()) {
                userModel.setAttribute("callSign", Collections.singletonList(callSign));
            }
            if (imoNumber != null && !imoNumber.trim().isEmpty()) {
                userModel.setAttribute("imoNumber", Collections.singletonList(imoNumber));
            }
            if (mmsiNumber != null && !mmsiNumber.trim().isEmpty()) {
                userModel.setAttribute("mmsiNumber", Collections.singletonList(mmsiNumber));
            }
            if (aisShipType != null && aisShipType.trim().isEmpty()) {
                userModel.setAttribute("aisShipType", Collections.singletonList(aisShipType));
            }
            if (portOfRegister != null && !portOfRegister.trim().isEmpty()) {
                userModel.setAttribute("portOfRegister", Collections.singletonList(portOfRegister));
            }
            if (shipMrn != null && !shipMrn.trim().isEmpty()) {
                userModel.setAttribute("shipMrn", Collections.singletonList(shipMrn));
            }
            if (mrnSubsidiary != null && !mrnSubsidiary.trim().isEmpty()) {
                userModel.setAttribute("mrnSubsidiary", Collections.singletonList(mrnSubsidiary));
            }
            if (homeMmsUrl != null && !homeMmsUrl.trim().isEmpty()) {
                userModel.setAttribute("homeMmsUrl", Collections.singletonList(homeMmsUrl));
            }
            if (url != null && !url.trim().isEmpty()) {
                userModel.setAttribute("url", Collections.singletonList(url));
            }
        }
    }

    @Override
    public void action(AuthenticationFlowContext authenticationFlowContext) {
        // empty
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
        // empty
    }
}
