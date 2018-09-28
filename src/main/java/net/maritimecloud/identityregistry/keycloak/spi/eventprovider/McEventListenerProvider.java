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
package net.maritimecloud.identityregistry.keycloak.spi.eventprovider;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.util.JsonSerialization;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class McEventListenerProvider implements EventListenerProvider {

    private static final Logger log = Logger.getLogger(McEventListenerProvider.class);

    public final static Pattern MRN_PATTERN = Pattern.compile("^urn:mrn:([a-z0-9()+,\\-.:=@;$_!*']|%[0-9a-f]{2})+$", Pattern.CASE_INSENSITIVE);

    private KeycloakSession session;
    private String serverRoot = "";
    private String keystorePath = "";
    private String keystorePassword = "";
    private String truststorePath = "";
    private String truststorePassword = "";
    private String[] idpNotToSync = null;

        public McEventListenerProvider(KeycloakSession session, String serverRoot, String keystorePath, String keystorePassword, String truststorePath, String truststorePassword, String[] idpNotToSync) {
        this.session = session;
        this.serverRoot = serverRoot;
        this.keystorePath = keystorePath;
        this.keystorePassword = keystorePassword;
        this.truststorePath = truststorePath;
        this.truststorePassword = truststorePassword;
        this.idpNotToSync = idpNotToSync;
    }

    public void close() {
        // TODO Auto-generated method stub
        
    }

    public void onEvent(Event event) {
        // We only worry about LOGIN events.
        if (event.getType() != EventType.LOGIN) {
            return;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("type=").append(event.getType()).append(", realmId=").append(event.getRealmId()).append(", clientId=").append(event.getClientId())
                .append(", userId=").append(event.getUserId()).append(", ipAddress=").append(event.getIpAddress());
        if (event.getError() != null) {
            sb.append(", error=").append(event.getError());
        }

        String identityProvider = null;
        if (event.getDetails() != null) {
            for (Map.Entry<String, String> e : event.getDetails().entrySet()) {
                if ("identity_provider".equals(e.getKey())) {
                    identityProvider = e.getValue();
                }
                if (log.isInfoEnabled()) {
                    sb.append(", ").append(e.getKey());
                    if (e.getValue() == null || e.getValue().indexOf(' ') == -1) {
                        sb.append("=").append(e.getValue());
                    } else {
                        sb.append("='").append(e.getValue()).append("'");
                    }
                }
            }
        }

        RealmModel realm;
        UserModel user = null;

        if (event.getRealmId() != null && event.getUserId() != null) {
            realm = session.realms().getRealm(event.getRealmId());
            user = session.users().getUserById(event.getUserId(), realm);
            // Get the roles and the organisations that the user can act on behalf of
            List<String> userRoles = getUserRoles(user.getUsername());
            user.setAttribute("roles", userRoles);
            List<String> actingOnBehalfOf = getActingOnBehalfOf(user.getUsername());
            user.setAttribute("actingOnBehalfOf", actingOnBehalfOf);
        }

        log.info("event info: " + sb.toString());

        // Only users coming from an identity provider is sync'ed.
        if (identityProvider == null) {
            log.info("no identity provider found for this user, so sync skipped!");
            return;
        }

        // we skip certain identity providers
        if (Arrays.binarySearch(idpNotToSync, identityProvider.toLowerCase()) >= 0) {
            log.info("this identity provider is setup not to be sync'ed, so sync skipped!");
            return;
        }

        if (event.getRealmId() != null && event.getUserId() != null) {
            User mcUser = new User();
            mcUser.setEmail(user.getEmail());
            mcUser.setFirstName(user.getFirstName());
            mcUser.setLastName(user.getLastName());
            // The username is in reality a mrn...
            mcUser.setMrn(user.getUsername());
            String orgMrn = null;
            List<String> orgList = user.getAttributes().get("org");
            if (orgList != null && orgList.size() > 0) {
                orgMrn = orgList.get(0);
            }
            if (orgMrn == null || orgMrn.isEmpty()) {
                log.warn("No org MRN found, skipping user sync");
                return;
            }
            List<String> permissionsList = user.getAttributes().get("permissions");
            if (permissionsList != null && permissionsList.size() > 0) {
                mcUser.setPermissions(String.join(", ", permissionsList));
            }
            // in case the user comes from an Identity Provider that hosts multiple organizations, the organization is
            // not always known, so some extra info is/can be given, which is then used for sync
            List<String> orgNameList = user.getAttributes().get("org-name");
            String orgName = null;
            if (orgNameList != null && orgNameList.size() > 0) {
                orgName = orgNameList.get(0);
            }
            List<String> orgAddressList = user.getAttributes().get("org-address");
            String orgAddress = null;
            if (orgAddressList != null && orgAddressList.size() > 0) {
                orgAddress = orgAddressList.get(0);
            }
            // Check if orgName is an MRN, in which case we extract the org shortname from the MRN and puts it
            // in the orgName. Also puts a dummy value in the orgAddress if needed.
            if (orgName != null && MRN_PATTERN.matcher(orgName).matches()) {
                int idx = orgMrn.lastIndexOf(":") + 1;
                orgName = orgMrn.substring(idx);
                if (orgAddress == null || orgAddress.isEmpty()) {
                    orgAddress = "A round the corner, The Seven Seas";
                }
            }
            if (user != null && user.getAttributes() != null) {
                for (Map.Entry<String, List<String>> e: user.getAttributes().entrySet()) {
                    log.info("user attr: " + e.getKey() + ", value: "  + String.join(", ", e.getValue()));
                }
            }
            sendUserUpdate(mcUser, orgMrn, orgName, orgAddress);
        }
    }

    protected List<String> getUserRoles(String userMrn) {
        if (serverRoot != null) {
            CloseableHttpClient client = buildHttpClient();
            if (client == null) {
                log.error("Could not get build http client to get user roles");
                return new ArrayList<>();
            }
            String uri = serverRoot + "/service/" + userMrn + "/roles";
            HttpGet get = new HttpGet(uri);
            CloseableHttpResponse response;
            try {
                response = client.execute(get);
                int status = response.getStatusLine().getStatusCode();
                HttpEntity entity = response.getEntity();
                if (status != 200) {
                    log.error("Getting user roles failed");
                } else {
                    String json = getContent(entity);
                    List<String> roles = (ArrayList<String>) JsonSerialization.readValue(json, List.class);
                    if (roles != null) {
                        return roles;
                    }
                }

            } catch (IOException e) {
                log.error("Threw exception", e);
            }
        }
        return new ArrayList<>();
    }

    protected List<String> getActingOnBehalfOf(String userMrn) {
        if (serverRoot != null) {
            CloseableHttpClient client = buildHttpClient();
            if (client == null) {
                log.error("Could not build http client");
                return new ArrayList<>();
            }
            String uri = serverRoot + "/service/" + userMrn + "/acting-on-behalf-of";
            HttpGet get = new HttpGet(uri);
            CloseableHttpResponse response;
            try {
                response = client.execute(get);
                int status = response.getStatusLine().getStatusCode();
                HttpEntity entity = response.getEntity();
                if (status != 200) {
                    log.error("Getting acting on behalf of orgs failed");
                } else {
                    String json = getContent(entity);
                    List<String> orgs = (ArrayList<String>) JsonSerialization.readValue(json, List.class);
                    if (orgs != null) {
                        return orgs;
                    }
                }
            } catch (IOException e) {
                log.error("Threw exception", e);
            }
        }
        return new ArrayList<>();
    }

    protected void sendUserUpdate(User user, String orgMrn, String orgName, String orgAddress) {
        CloseableHttpClient client = buildHttpClient();
        if (client == null) {
            return;
        }
        String uri = serverRoot + "/x509/api/org/" + orgMrn + "/user-sync/";
        if (orgName != null && orgAddress != null) {
            try {
                uri += "?org-name=" + URLEncoder.encode(orgName, "UTF-8") + "&org-address=" + URLEncoder.encode(orgAddress, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                log.error("Threw exception", e);
                return;
            }
        }
        HttpPost post = new HttpPost(uri);
        CloseableHttpResponse response = null;
        try {
            String serializedUser = JsonSerialization.writeValueAsString(user);
            StringEntity input = new StringEntity(serializedUser, ContentType.APPLICATION_JSON);
            input.setContentType("application/json");
            post.setEntity(input);
            log.info("user json: " + serializedUser);
            log.info("uri: " + uri);
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
                log.error("Threw exception", e);
            }
        }
    }

    protected String getContent(HttpEntity entity) {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        try {
            entity.writeTo(os);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            throw new RuntimeException(e);
        }
        byte[] bytes = os.toByteArray();
        String data = new String(bytes);
        return data;
    }

    protected CloseableHttpClient buildHttpClient() {
        log.info("keystore path: " + keystorePath);
        log.info("truststorePath path: " + truststorePath);
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
        } catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
            log.error("Threw exception", e);
            throw new RuntimeException(e);
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
        } catch (KeyManagementException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException e) {
            log.error("Threw exception", e);
            throw new RuntimeException(e);
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
