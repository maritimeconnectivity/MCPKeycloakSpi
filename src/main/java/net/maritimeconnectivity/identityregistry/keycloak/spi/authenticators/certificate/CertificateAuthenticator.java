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
import lombok.extern.jbosslog.JBossLog;
import net.maritimeconnectivity.pki.CertificateHandler;
import net.maritimeconnectivity.pki.PKIIdentity;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.authentication.Authenticator;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@JBossLog
@NoArgsConstructor
public class CertificateAuthenticator implements Authenticator {

    /**
     * Converts the certificate in the header to a Keycloak User.
     * It is assumed that the certificate is verified by the reserve proxy (nginx) in front of keycloak.
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
        if (user.getMrn() == null) {
            log.warn("Extraction of data from the certificate failed!");
            throw new AuthenticationFlowException("Extraction of data from the certificate failed!", AuthenticationFlowError.INVALID_USER);
        }

        // Check for required data
        String mrn = user.getMrn();
        String fullName = user.getCn();
        String orgMrn = user.getO();
        String email = user.getEmail();
        String uid = user.getDn();
        if (fullName == null || fullName.isEmpty() || mrn == null || mrn.trim().isEmpty() || orgMrn == null
                || orgMrn.isEmpty() || uid == null || uid.trim().isEmpty()) {
            log.warn("Required data is not available in client certificate!");
            throw new AuthenticationFlowException("Required data is not available in client certificate!", AuthenticationFlowError.INVALID_USER);
        }
        KeycloakSession session = authenticationFlowContext.getSession();
        RealmModel realm = authenticationFlowContext.getRealm();
        String permissions = user.getPermissions();
        String mrnSubsidiary = user.getMrnSubsidiary();
        String homeMmsUrl = user.getHomeMmsUrl();

        // Try to find existing user
        UserModel existingUser = session.users().getUserByUsername(realm, mrn);
        if (existingUser == null) {
            log.debugf("No duplication detected. Creating account for user '%s'.", mrn);

            UserModel federatedUser = session.users().addUser(realm, mrn);
            federatedUser.setEnabled(true);
            if (email != null && !email.trim().isEmpty()) {
                federatedUser.setEmail(email);
            }
            federatedUser.setFirstName(user.getFirstName());
            federatedUser.setLastName(user.getLastName());

            setUserAttributes(authenticationFlowContext, user, mrn, orgMrn, permissions, uid, mrnSubsidiary, homeMmsUrl, federatedUser);
        } else {
            log.debugf("Existing user detected with %s '%s' .", UserModel.USERNAME, existingUser.getUsername());

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
            setUserAttributes(authenticationFlowContext, user, mrn, orgMrn, permissions, uid, mrnSubsidiary, homeMmsUrl, existingUser);
        }
        authenticationFlowContext.success();
        log.debug("Authentication flow successfully completed!");
    }

    private void setUserAttributes(AuthenticationFlowContext authenticationFlowContext, PKIIdentity user, String mrn, String orgMrn, String permissions, String uid, String mrnSubsidiary, String homeMmsUrl, UserModel userModel) {
        if (permissions != null && !permissions.trim().isEmpty()) {
            log.debug("About to set permissions attr to: " + permissions);
            userModel.setAttribute("permissions", Collections.singletonList(permissions));
            log.debug("Just set permissions attr to: " + permissions);
        }

        log.debug("About to set mrn attr to: " + mrn);
        userModel.setAttribute("mrn", Collections.singletonList(mrn));
        log.debug("Just set mrn attr to: " + mrn);

        log.debug("About to set uid attr to: " + uid);
        userModel.setAttribute("uid", Collections.singletonList(uid));
        log.debug("Just set uid attr to: " + uid);

        if (!orgMrn.trim().isEmpty()) {
            log.debug("About to set org attr to: " + orgMrn);
            userModel.setAttribute("org", Collections.singletonList(orgMrn));
            log.debug("Just set org attr to: " + orgMrn);
        }

        if (mrnSubsidiary != null && !mrnSubsidiary.trim().isEmpty()) {
            log.debug("About to set subsidiary_mrn attr to: " + mrnSubsidiary);
            userModel.setAttribute("subsidiary_mrn", Collections.singletonList(mrnSubsidiary));
            log.debug("Just set subsidiary_mrn attr to: " + mrnSubsidiary);
        }

        if (homeMmsUrl != null && !homeMmsUrl.trim().isEmpty()) {
            log.debug("About to set mms_url attr to: " + homeMmsUrl);
            userModel.setAttribute("mms_url", Collections.singletonList(homeMmsUrl));
            log.debug("Just set mms_url attr to: " + homeMmsUrl);
        }

        extractNonUserAttributes(user, userModel);

        authenticationFlowContext.setUser(userModel);
    }

    private void extractNonUserAttributes(PKIIdentity user, UserModel userModel) {
        String flagState = user.getFlagState();
        String callSign = user.getCallSign();
        String imoNumber = user.getImoNumber();
        String mmsiNumber = user.getMmsiNumber();
        String aisShipType = user.getAisShipType();
        String portOfRegister = user.getPortOfRegister();
        String shipMrn = user.getShipMrn();
        String url = user.getUrl();

        if (flagState != null && !flagState.trim().isEmpty()) {
            userModel.setAttribute("flagstate", Collections.singletonList(flagState));
        }
        if (callSign != null && !callSign.trim().isEmpty()) {
            userModel.setAttribute("callsign", Collections.singletonList(callSign));
        }
        if (imoNumber != null && !imoNumber.trim().isEmpty()) {
            userModel.setAttribute("imo_number", Collections.singletonList(imoNumber));
        }
        if (mmsiNumber != null && !mmsiNumber.trim().isEmpty()) {
            userModel.setAttribute("mmsi", Collections.singletonList(mmsiNumber));
        }
        if (aisShipType != null && !aisShipType.trim().isEmpty()) {
            userModel.setAttribute("ais_type", Collections.singletonList(aisShipType));
        }
        if (portOfRegister != null && !portOfRegister.trim().isEmpty()) {
            userModel.setAttribute("registered_port", Collections.singletonList(portOfRegister));
        }
        if (shipMrn != null && !shipMrn.trim().isEmpty()) {
            userModel.setAttribute("ship_mrn", Collections.singletonList(shipMrn));
        }
        if (url != null && !url.trim().isEmpty()) {
            userModel.setAttribute("url", Collections.singletonList(url));
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
