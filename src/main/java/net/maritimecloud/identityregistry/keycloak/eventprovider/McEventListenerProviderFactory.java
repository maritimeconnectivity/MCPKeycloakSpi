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
package net.maritimecloud.identityregistry.keycloak.eventprovider;

import org.keycloak.Config.Scope;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class McEventListenerProviderFactory implements EventListenerProviderFactory {

    private String serverRoot = "";
    private String keystorePath = "";
    private String keystorePassword = "";
    private String truststorePath = "";
    private String truststorePassword = "";

    public String getId() {
        return "mc-event-listener";
    }

    public void init(Scope config) {
        serverRoot = config.get("server-root");
        keystorePath = config.get("keystore-path");
        keystorePassword = config.get("keystore-password");
        truststorePath = config.get("truststore-path");
        truststorePassword = config.get("truststore-password");
    }

    public void close() {
        // TODO Auto-generated method stub
        
    }

    public EventListenerProvider create(KeycloakSession session) {
        return new McEventListenerProvider(session, serverRoot, keystorePath, keystorePassword, truststorePath, truststorePassword);
    }

    public void postInit(KeycloakSessionFactory arg0) {
        // TODO Auto-generated method stub
        
    }
}
