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

import net.maritimecloud.identityregistry.keycloak.spi.authenticators.certificate.utils.CertificateUtil;
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

    private String truststorePath = "";
    private String truststorePassword = "";

    private static final Logger log = Logger.getLogger(CertificateAuthenticator.class);

    public CertificateAuthenticator(String truststorePath, String truststorePassword) {
        this.truststorePath = truststorePath;
        this.truststorePassword = truststorePassword;
    }

    @Override
    public void authenticate(AuthenticationFlowContext authenticationFlowContext) {
        // Get the client certificate from the HTTP header
        HttpRequest req = authenticationFlowContext.getHttpRequest();
        List<String> certStrList = req.getHttpHeaders().getRequestHeader("X-Client-Certificate");
        if (certStrList.size() != 1) {
            throw new AuthenticationFlowException("No client certificate detected!", AuthenticationFlowError.INVALID_USER);
        }
        // Convert the header string to a certificate
        CertificateUtil certUtil = new CertificateUtil(this.truststorePath, this.truststorePassword);
        X509Certificate userCertificate = certUtil.getCertFromString(certStrList.get(0));
        if (userCertificate == null) {
            throw new AuthenticationFlowException("Could not read client certificate!", AuthenticationFlowError.INVALID_USER);
        }
        // Actually authenticate certificate against root cert.
        if (!certUtil.verifyCertificate(userCertificate)) {
            throw new AuthenticationFlowException("Could not validate client certificate!", AuthenticationFlowError.INVALID_USER);
        }
        // Get user details from the certificate
        Map<String, String> user = certUtil.getUserFromCert(userCertificate);
        if (user == null || user.isEmpty()) {
            throw new AuthenticationFlowException("Extraction of data from the certificate failed!", AuthenticationFlowError.INVALID_USER);
        }

        // Check for required data
        String fullname = user.get("fullname");
        String orgUserName = user.get("orgUserName");
        String org = user.get("org");
        if (fullname == null || fullname.isEmpty() || orgUserName == null || orgUserName.isEmpty() || org == null || org.isEmpty()) {
            throw new AuthenticationFlowException("Required data is not available in client certificate!", AuthenticationFlowError.INVALID_USER);
        }
        KeycloakSession session = authenticationFlowContext.getSession();
        RealmModel realm = authenticationFlowContext.getRealm();

        // Try to find existing user
        UserModel existingUser = session.users().getUserByUsername(orgUserName, authenticationFlowContext.getRealm());
        if (existingUser == null) {
            //log.debugf("No duplication detected. Creating account for user '%s' and linking with identity provider '%s' .",
            //        username, brokerContext.getIdpConfig().getAlias());

            UserModel federatedUser = session.users().addUser(realm, orgUserName);
            federatedUser.setEnabled(true);
            federatedUser.setEmail(user.get("email"));
            federatedUser.setFirstName(user.get("firstName"));
            federatedUser.setLastName(user.get("lastName"));

            federatedUser.setAttribute("permissions", Arrays.asList(user.get("permissions")));
            federatedUser.setAttribute("mrn", Arrays.asList(user.get("mrn")));
            federatedUser.setAttribute("org", Arrays.asList(user.get("orgShortName")));

            authenticationFlowContext.setUser(federatedUser);
            //context.getClientSession().setNote(BROKER_REGISTERED_NEW_USER, "true");
            authenticationFlowContext.success();
        } else {
            log.debugf("Duplication detected. There is already existing user with %s '%s' .", UserModel.USERNAME, existingUser.getUsername());

            existingUser.setEmail(user.get("email"));
            existingUser.setFirstName(user.get("firstName"));
            existingUser.setLastName(user.get("lastName"));

            // Clear existing attributes
            for (Map.Entry<String, List<String>> attr : existingUser.getAttributes().entrySet()) {
                existingUser.removeAttribute(attr.getKey());
            }
            existingUser.setAttribute("permissions", Arrays.asList(user.get("permissions")));
            existingUser.setAttribute("mrn", Arrays.asList(user.get("mrn")));
            existingUser.setAttribute("org", Arrays.asList(user.get("orgShortName")));

            authenticationFlowContext.setUser(existingUser);
            //context.getClientSession().setNote(BROKER_REGISTERED_NEW_USER, "true");
            authenticationFlowContext.success();
        }
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
