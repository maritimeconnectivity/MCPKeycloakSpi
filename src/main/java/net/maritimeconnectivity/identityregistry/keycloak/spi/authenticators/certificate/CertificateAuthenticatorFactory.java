/*
 * Copyright 2017 Danish Maritime Authority.
 * Copyright 2020 Maritime Connectivity Platform Consortium
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

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;


public class CertificateAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "certificate";
    static CertificateAuthenticator singleton = null;
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    @Override
    public Authenticator create(KeycloakSession session) {
        return singleton;
    }

    @Override
    public void init(Config.Scope config) {
        String clientCertHeader = config.get("client-cert-header");
        if (clientCertHeader == null || clientCertHeader.isBlank()) {
            clientCertHeader = "X-Client-Certificate";
        }
        if (singleton == null) {
            singleton = new CertificateAuthenticator(clientCertHeader);
        }
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // empty
    }

    @Override
    public void close() {
        // empty
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getReferenceCategory() {
        return PROVIDER_ID;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED};

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getDisplayType() {
        return "Certificates";
    }

    @Override
    public String getHelpText() {
        return "Authenticate users based on X.509 certificates.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

}
