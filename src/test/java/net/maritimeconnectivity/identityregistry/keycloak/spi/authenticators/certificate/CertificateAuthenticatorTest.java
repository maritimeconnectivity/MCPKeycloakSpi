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

import org.jboss.resteasy.spi.HttpRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;

import javax.ws.rs.core.HttpHeaders;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;


class CertificateAuthenticatorTest {

    private AuthenticationFlowContext mockedAuthFlowContext;

    private HttpRequest mockedHttpRequest;

    private HttpHeaders mockedHttpHeaders;

    private KeycloakSession mockedKeycloakSession;

    private RealmModel mockedRealmModel;

    private UserProvider mockedUserProvider;

    private CertificateAuthenticator certificateAuthenticator;

    @BeforeEach
    void setUp() {
        // Set up needed mocked objects
        this.mockedAuthFlowContext = mock(AuthenticationFlowContext.class);
        this.mockedHttpRequest = mock(HttpRequest.class);
        this.mockedHttpHeaders = mock(HttpHeaders.class);
        this.mockedKeycloakSession = mock(KeycloakSession.class);
        this.mockedRealmModel = mock(RealmModel.class);
        this.mockedUserProvider = mock(UserProvider.class);

        // Set up needed mocked return
        given(this.mockedAuthFlowContext.getHttpRequest()).willReturn(this.mockedHttpRequest);
        given(this.mockedAuthFlowContext.getSession()).willReturn(this.mockedKeycloakSession);
        given(this.mockedAuthFlowContext.getRealm()).willReturn(this.mockedRealmModel);
        given(this.mockedHttpRequest.getHttpHeaders()).willReturn(this.mockedHttpHeaders);
        given(this.mockedKeycloakSession.users()).willReturn(this.mockedUserProvider);

        // Create the CertificateAuthenticator to test
        this.certificateAuthenticator = new CertificateAuthenticator();
    }

    /**
     * Test the authentication works when user does not already exists
     */
    @Test
    void testAuthenticateNewUser() throws Exception {
        // Load the nginx
        String nginxFormatedPemCert = loadTxtFile("src/test/resources/thc-cert-nginx-format.pem");
        // "Inject" the certificate in the mocked httpheaders
        given(this.mockedHttpHeaders.getRequestHeader("X-Client-Certificate")).willReturn(Collections.singletonList(nginxFormatedPemCert));
        // Set the mocked UserProvide to return null when looking for existing user - this should trigger creation of new user
        given(this.mockedUserProvider.getUserByUsername(any(RealmModel.class), any(String.class))).willReturn(null);
        // Create a mocked UserModel that is returned when creating the new user.
        UserModel mockedUserModel = mock(UserModel.class);
        given(this.mockedUserProvider.addUser(any(), any())).willReturn(mockedUserModel);

        // Run the authenticator
        this.certificateAuthenticator.authenticate(this.mockedAuthFlowContext);

        // Verify that the user has been created correctly
        verify(mockedUserModel, times(1)).setEnabled(true);
        verify(mockedUserModel, times(1)).setFirstName("Thomas");
        verify(mockedUserModel, times(1)).setLastName("Christensen");
        verify(mockedUserModel, times(1)).setAttribute("permissions", Collections.singletonList("NONE"));
        verify(mockedUserModel, times(1)).setAttribute("mrn", Collections.singletonList("urn:mrn:mcl:user:dma:thc"));
    }


    /**
     * Test the authentication works when user does not already exists
     */
    @Test
    void testAuthenticateUpdateUser() throws Exception {
        // Load the nginx
        String nginxFormatedPemCert = loadTxtFile("src/test/resources/thc-cert-nginx-format.pem");
        // "Inject" the certificate in the mocked httpheaders
        given(this.mockedHttpHeaders.getRequestHeader("X-Client-Certificate")).willReturn(Collections.singletonList(nginxFormatedPemCert));
        // Create a mocked UserModel that is returned when looking for existing user
        UserModel mockedUserModel = mock(UserModel.class);
        given(this.mockedUserProvider.getUserByUsername(any(RealmModel.class), any(String.class))).willReturn(mockedUserModel);

        // Run the authenticator
        this.certificateAuthenticator.authenticate(this.mockedAuthFlowContext);

        // Verify that the user has been updated correctly
        verify(mockedUserModel, times(1)).setFirstName("Thomas");
        verify(mockedUserModel, times(1)).setLastName("Christensen");
        verify(mockedUserModel, times(1)).setAttribute("permissions", Collections.singletonList("NONE"));
        verify(mockedUserModel, times(1)).setAttribute("mrn", Collections.singletonList("urn:mrn:mcl:user:dma:thc"));
    }

    /**
     * Test the authentication fails if the certificate is missing
     */
    @Test
    void testAuthenticateNoCert() throws Exception {
        // "Inject" the missing certificate in the mocked httpheaders
        given(this.mockedHttpHeaders.getRequestHeader("X-Client-Certificate")).willReturn(Collections.emptyList());

        // Run the authenticator and expect an exception
        Throwable exception = assertThrows(AuthenticationFlowException.class, () -> {
            this.certificateAuthenticator.authenticate(this.mockedAuthFlowContext);
        });
        assertEquals("No client certificate detected!", exception.getMessage());
    }

    /**
     * Test the authentication fails if the certificate is incomplete
     */
    @Test
    void testAuthenticateIncompleteCert() {
        // "Inject" the missing certificate in the mocked httpheaders
        given(this.mockedHttpHeaders.getRequestHeader("X-Client-Certificate")).willReturn(Collections.singletonList("ASDFGHJKJHGFDSASDFGHJKL"));

        // Run the authenticator and expect an exception
        Throwable exception = assertThrows(AuthenticationFlowException.class, () -> {
            this.certificateAuthenticator.authenticate(this.mockedAuthFlowContext);
        });
        assertEquals("Could not read client certificate!", exception.getMessage());
    }


    /**
     * Helper method to load data from txt file
     *
     * @param path
     * @return
     */
    public static String loadTxtFile(String path) {
        try {
            return Files.lines(Paths.get(path)).collect(Collectors.joining("\n"));
        } catch (IOException e) {
            e.printStackTrace();
            fail("Loading Certificate from file failed!");
            throw new RuntimeException(e);
        }
    }
}
