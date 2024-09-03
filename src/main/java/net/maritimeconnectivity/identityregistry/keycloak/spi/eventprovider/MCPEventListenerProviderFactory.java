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
package net.maritimeconnectivity.identityregistry.keycloak.spi.eventprovider;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class MCPEventListenerProviderFactory implements EventListenerProviderFactory {

    public static final String ID = "mcpEventListener";

    private String serverRoot = "";
    private String keystorePath = "";
    private String keystorePassword = "";
    private String truststorePath = "";
    private String truststorePassword = "";
    private String[] idpNotToSync = null;

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public void init(Config.Scope config) {
        serverRoot = config.get("server-root");
        keystorePath = config.get("keystore-path");
        keystorePassword = config.get("keystore-password");
        truststorePath = config.get("truststore-path");
        truststorePassword = config.get("truststore-password");
        String idpNotToSyncStr = config.get("idp-not-to-sync");
        if (idpNotToSyncStr != null && !idpNotToSyncStr.trim().isEmpty()) {
            idpNotToSync = idpNotToSyncStr.split(",");
        }
    }

    @Override
    public void close() {
        // empty
    }

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new MCPEventListenerProvider(session, serverRoot, keystorePath, keystorePassword, truststorePath, truststorePassword, idpNotToSync);
    }

    @Override
    public void postInit(KeycloakSessionFactory arg0) {
        // empty
    }
}
