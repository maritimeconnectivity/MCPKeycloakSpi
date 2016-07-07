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
package net.maritimecloud.identityregistry.keycloak.spi.eventprovider;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;

import javax.net.ssl.SSLContext;

import org.apache.http.HttpEntity;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.util.JsonSerialization;
import org.jboss.logging.Logger;

public class McEventListenerProvider implements EventListenerProvider {

    private static final Logger log = Logger.getLogger(McEventListenerProvider.class);

    private KeycloakSession session;
    private String serverRoot = "";
    private String keystorePath = "";
    private String keystorePassword = "";
    private String truststorePath = "";
    private String truststorePassword = "";

    public McEventListenerProvider(KeycloakSession session, String serverRoot, String keystorePath, String keystorePassword, String truststorePath, String truststorePassword) {
        this.session = session;
        this.serverRoot = serverRoot;
        this.keystorePath = keystorePath;
        this.keystorePassword = keystorePassword;
        this.truststorePath = truststorePath;
        this.truststorePassword = truststorePassword;
    }

    public void close() {
        // TODO Auto-generated method stub
        
    }

    public void onEvent(Event event) {
        // We only worry about IDENTITY_PROVIDER_LOGIN events.
        if (event.getType() != EventType.IDENTITY_PROVIDER_LOGIN) {
            return;
        }
        StringBuilder sb = new StringBuilder();

        sb.append("type=");
        sb.append(event.getType());
        sb.append(", realmId=");
        sb.append(event.getRealmId());
        sb.append(", clientId=");
        sb.append(event.getClientId());
        sb.append(", userId=");
        sb.append(event.getUserId());
        sb.append(", ipAddress=");
        sb.append(event.getIpAddress());

        if (event.getError() != null) {
            sb.append(", error=");
            sb.append(event.getError());
        }

        if (event.getDetails() != null) {
            for (Map.Entry<String, String> e : event.getDetails().entrySet()) {
                sb.append(", ");
                sb.append(e.getKey());
                if (e.getValue() == null || e.getValue().indexOf(' ') == -1) {
                    sb.append("=");
                    sb.append(e.getValue());
                } else {
                    sb.append("='");
                    sb.append(e.getValue());
                    sb.append("'");
                }
            }
        }
        log.info("event info: " + sb.toString());
        if (event.getRealmId() != null && event.getUserId() != null) {
            RealmModel realm = session.realms().getRealm(event.getRealmId());
            UserModel user = session.users().getUserById(event.getUserId(), realm);
            User mcUser = new User();
            mcUser.setEmail(user.getEmail());
            mcUser.setFirstName(user.getFirstName());
            mcUser.setLastName(user.getLastName());
            String orgShortName = null;
            if (event.getType() == EventType.IDENTITY_PROVIDER_LOGIN) {
                // The username should be in the form "<org-shortname>.<user-unique-org-id>"
                String[] splitName = user.getUsername().split(".", 1);
                if (splitName.length == 2) {
                    orgShortName = splitName[0].toUpperCase();
                    mcUser.setUserOrgId(splitName[1]);
                } else {
                    return;
                }
            } else {
                // TODO: This is for testing only!! Remove again!! 
                List<String> orgList = user.getAttributes().get("org");
                if (orgList != null && orgList.size() > 0) {
                    orgShortName = orgList.get(0);
                }
                mcUser.setUserOrgId(user.getUsername());
            }
            if (orgShortName == null || orgShortName.isEmpty()) {
                log.warn("No org shortname found, skipping user sync");
                return;
            }
            List<String> permissionsList = user.getAttributes().get("permissions");
            if (permissionsList != null && permissionsList.size() > 0) {
                mcUser.setPermissions(String.join(", ", permissionsList));
            }
            
            if (user != null && user.getAttributes() != null) {
                for (Map.Entry<String, List<String>> e: user.getAttributes().entrySet()) {
                    log.info("user attr: " + e.getKey() + ", value: "  + String.join(", ", e.getValue()));
                }
            }
            sendUserUpdate(mcUser, orgShortName);
        }
    }

    private void sendUserUpdate(User user, String orgShortName) {
        CloseableHttpClient client = buildHttpClient();
        if (client == null) {
            return;
        }
        HttpPost post = new HttpPost(serverRoot + "/x509/api/org/" + orgShortName + "/user-sync/");
        CloseableHttpResponse response = null;
        try {
            String serializedUser = JsonSerialization.writeValueAsString(user);
            StringEntity input = new StringEntity(serializedUser);
            input.setContentType("application/json");
            post.setEntity(input);
            log.info("user json: " + serializedUser);
            response = client.execute(post);
            int status = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (status != 200) {
                String json = getContent(entity);
                String error = "User sync failed. Bad status: " + status + " response: " + json;
                log.error(error);
            } else {
                log.info("User sync'ed!");
            }
        } catch (ClientProtocolException e) {
            log.error("Threw exception", e);
        } catch (IOException e) {
            log.error("Threw exception", e);
        } finally {
            try {
                if (response != null) {
                    response.close();
                }
                client.close();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
    }

    private String getContent(HttpEntity entity) {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        try {
            entity.writeTo(os);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return "";
        }
        byte[] bytes = os.toByteArray();
        String data = new String(bytes);
        return data;
    }

    private CloseableHttpClient buildHttpClient() {
        KeyStore keyStore = null;
        KeyStore trustStore = null;
        FileInputStream instreamKeystore = null;
        FileInputStream instreamTruststore = null;
        try {
            keyStore = KeyStore.getInstance("jks");
            instreamKeystore = new FileInputStream(keystorePath);
            keyStore.load(instreamKeystore, keystorePassword.toCharArray());
            if (truststorePath != null && !truststorePath.isEmpty()) {
                trustStore = KeyStore.getInstance("jks");
                instreamTruststore = new FileInputStream(truststorePath);
                trustStore.load(instreamTruststore, truststorePassword.toCharArray());
            }
        } catch (NoSuchAlgorithmException e) {
            log.error("Threw exception", e);
            return null;
        } catch (CertificateException e) {
            log.error("Threw exception", e);
            return null;
        } catch (IOException e) {
            log.error("Threw exception", e);
            return null;
        } catch (KeyStoreException e) {
            log.error("Threw exception", e);
            return null;
        } finally {
            try {
                if (instreamKeystore != null) {
                    instreamKeystore.close();
                }
                if (instreamTruststore != null) {
                    instreamTruststore.close();
                }
            } catch (IOException e) {
                log.error("Threw exception", e);
            }
        }

        // Trust own CA and all self-signed certs
        SSLContext sslcontext;
        try {
            SSLContextBuilder sslContextBuilder = SSLContexts.custom();
            sslContextBuilder.loadKeyMaterial(keyStore, keystorePassword.toCharArray());
            // If you have a trust store - should only be needed when the site we contact use self-signed certificates.
            if (trustStore != null) {
                sslContextBuilder.loadTrustMaterial(trustStore, new TrustSelfSignedStrategy());
            }
            sslContextBuilder.loadKeyMaterial(keyStore, keystorePassword.toCharArray());
            sslcontext = sslContextBuilder.build();
        } catch (KeyManagementException e) {
            log.error("Threw exception", e);
            return null;
        } catch (UnrecoverableKeyException e) {
            log.error("Threw exception", e);
            return null;
        } catch (NoSuchAlgorithmException e) {
            log.error("Threw exception", e);
            return null;
        } catch (KeyStoreException e) {
            log.error("Threw exception", e);
            return null;
        }
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext, new NoopHostnameVerifier());
        CloseableHttpClient httpclient = HttpClients.custom()
                                                    .setSSLSocketFactory(sslsf)
                                                    .build();
        return httpclient;
    }

    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        // TODO Auto-generated method stub
        
    }

}
