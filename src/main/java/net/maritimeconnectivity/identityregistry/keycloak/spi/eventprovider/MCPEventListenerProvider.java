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
package net.maritimeconnectivity.identityregistry.keycloak.spi.eventprovider;

import com.fasterxml.jackson.core.type.TypeReference;
import lombok.extern.jbosslog.JBossLog;
import net.maritimeconnectivity.identityregistry.keycloak.spi.exceptions.McpException;
import net.maritimeconnectivity.pki.PKIIdentity;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.client5.http.ssl.TrustSelfSignedStrategy;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.ssl.TLS;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.ssl.SSLContexts;
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
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

@JBossLog
public class MCPEventListenerProvider implements EventListenerProvider {

    public static final Pattern MRN_PATTERN = Pattern.compile("^urn:mrn:([a-z0-9()+,\\-.:=@;$_!*']|%[0-9a-f]{2})+$", Pattern.CASE_INSENSITIVE);

    private final KeycloakSession session;
    private final String serverRoot;
    private final String keystorePath;
    private final String keystorePassword;
    private final String truststorePath;
    private final String truststorePassword;
    private final String[] idpNotToSync;

    private final TypeReference<ArrayList<String>> arrayListTypeReference = new TypeReference<>() {};
    private final String servicePath;

    public MCPEventListenerProvider(KeycloakSession session, String serverRoot, String keystorePath, String keystorePassword, String truststorePath, String truststorePassword, String[] idpNotToSync) {
        this.session = session;
        this.serverRoot = serverRoot;
        this.keystorePath = keystorePath;
        this.keystorePassword = keystorePassword;
        this.truststorePath = truststorePath;
        this.truststorePassword = truststorePassword;
        this.idpNotToSync = idpNotToSync;
        this.servicePath = serverRoot + "/service/";
    }

    @Override
    public void close() {
        // not needed
        
    }

    @Override
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
                if (log.isDebugEnabled()) {
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

        List<String> userRoles = new ArrayList<>();
        List<String> actingOnBehalfOf = new ArrayList<>();
        try (CloseableHttpClient httpClient = buildHttpClient()) {
            PKIIdentity pkiIdentity = null;
            String userUid = null;

            if (event.getRealmId() != null && event.getUserId() != null) {
                realm = session.realms().getRealm(event.getRealmId());
                user = session.users().getUserById(realm, event.getUserId());
                // TODO: this should be removed when we move to the new implementation of the MSR
                // check that it is actually a user
                if (user != null && user.getUsername().contains(":user:")) {
                    // Get the roles and the organisations that the user can act on behalf of
                    getUserRolesAndActingOnBehalfOf(userRoles, actingOnBehalfOf, user, httpClient);
                    List<String> uidList = user.getAttributes().get("uid");
                    if (uidList == null || uidList.isEmpty()) {
                        pkiIdentity = getPKIIdentity(user.getUsername(), user, httpClient);
                        userUid = pkiIdentity.getDn();
                    }
                }

            }

            log.debug("event info: " + sb);

            // Only users coming from an identity provider is sync'ed.
            if (identityProvider == null) {
                log.debug("no identity provider found for this user, so sync skipped!");
                return;
            }

            // we skip certain identity providers
            if (Arrays.binarySearch(idpNotToSync, identityProvider.toLowerCase()) >= 0) {
                log.debugf("The identity provider \"%s\" is setup not to be sync'ed, so sync skipped!", identityProvider);
                return;
            }

            if (event.getRealmId() != null && event.getUserId() != null && user != null) {
                User mcUser = new User();
                mcUser.setEmail(user.getEmail());
                mcUser.setFirstName(user.getFirstName());
                mcUser.setLastName(user.getLastName());
                // The username is in reality a mrn...
                mcUser.setMrn(user.getUsername());
                String orgMrn = null;
                List<String> orgList = user.getAttributes().get("org");
                if (orgList != null && !orgList.isEmpty()) {
                    orgMrn = orgList.get(0);
                }
                if (orgMrn == null || orgMrn.isEmpty()) {
                    log.warn("No org MRN found, skipping user sync");
                    return;
                }
                List<String> permissionsList = user.getAttributes().get("permissions");
                if (permissionsList != null && !permissionsList.isEmpty()) {
                    mcUser.setPermissions(String.join(", ", permissionsList));
                }
                // in case the user comes from an Identity Provider that hosts multiple organizations, the organization is
                // not always known, so some extra info is/can be given, which is then used for sync
                List<String> orgNameList = user.getAttributes().get("org-name");
                String orgName = null;
                if (orgNameList != null && !orgNameList.isEmpty()) {
                    orgName = orgNameList.get(0);
                }
                List<String> orgAddressList = user.getAttributes().get("org-address");
                String orgAddress = null;
                if (orgAddressList != null && !orgAddressList.isEmpty()) {
                    orgAddress = orgAddressList.get(0);
                }
                // Check if orgName is an MRN, in which case we extract the org shortname from the MRN and puts it
                // in the orgName. Also puts a dummy value in the orgAddress if needed.
                if (orgName != null && MRN_PATTERN.matcher(orgName).matches()) {
                    int idx = orgMrn.lastIndexOf(':') + 1;
                    orgName = orgMrn.substring(idx);
                    if (orgAddress == null || orgAddress.isEmpty()) {
                        orgAddress = "A round the corner, The Seven Seas";
                    }
                }
                if (user.getAttributes() != null) {
                    for (Map.Entry<String, List<String>> e : user.getAttributes().entrySet()) {
                        log.debugf("user attr: %s, value: %s", e.getKey(), String.join(", ", e.getValue()));
                    }
                }
                sendUserUpdate(mcUser, orgMrn, orgName, orgAddress, httpClient);

                // TODO: this should be removed when we move to the new implementation of the MSR
                // If the user is new we need to get roles and orgs to act on behalf of after it has been synced
                if (userRoles.isEmpty() && actingOnBehalfOf.isEmpty() && user.getUsername().contains(":user:")) {
                    // Get the roles and the organisations that the user can act on behalf of
                    getUserRolesAndActingOnBehalfOf(userRoles, actingOnBehalfOf, user, httpClient);
                }
                if ((pkiIdentity == null || userUid == null || userUid.equals("")) && user.getUsername().contains(":user:")) {
                    getPKIIdentity(user.getUsername(), user, httpClient);
                }
            }
        } catch (IOException e) {
            log.error("Could not close HTTP client", e);
        }
    }

    protected void getUserRolesAndActingOnBehalfOf(List<String> userRoles, List<String> actingOnBehalfOf, UserModel user, CloseableHttpClient httpClient) {
        userRoles.addAll(getUserRoles(user.getUsername(), httpClient));
        user.setAttribute("roles", userRoles);
        actingOnBehalfOf.addAll(getActingOnBehalfOf(user.getUsername(), httpClient));
        user.setAttribute("actingOnBehalfOf", actingOnBehalfOf);
    }

    protected List<String> getUserRoles(String userMrn, CloseableHttpClient httpClient) {
        if (serverRoot != null) {
            if (httpClient == null) {
                log.error("Could not build http client to get user roles");
                return new ArrayList<>();
            }
            String uri = servicePath + userMrn + "/roles";
            HttpGet get = new HttpGet(uri);
            try (CloseableHttpResponse response = httpClient.execute(get)) {
                int status = response.getCode();
                HttpEntity entity = response.getEntity();
                if (status != 200) {
                    log.error("Getting user roles failed");
                } else {
                    String json = getContent(entity);
                    List<String> roles = JsonSerialization.readValue(json, arrayListTypeReference);
                    if (roles != null) {
                        return roles;
                    }
                }

            } catch (IOException e) {
                log.error("Could not get user roles", e);
            }
        }
        return new ArrayList<>();
    }

    protected List<String> getActingOnBehalfOf(String userMrn, CloseableHttpClient httpClient) {
        if (serverRoot != null) {
            if (httpClient == null) {
                log.error("Could not build http client");
                return new ArrayList<>();
            }
            String uri = servicePath + userMrn + "/acting-on-behalf-of";
            HttpGet get = new HttpGet(uri);
            try (CloseableHttpResponse response = httpClient.execute(get)) {
                int status = response.getCode();
                HttpEntity entity = response.getEntity();
                if (status != 200) {
                    log.error("Getting acting on behalf of orgs failed");
                } else {
                    String json = getContent(entity);
                    List<String> orgs = JsonSerialization.readValue(json, arrayListTypeReference);
                    if (orgs != null) {
                        return orgs;
                    }
                }
            } catch (IOException e) {
                log.error("Could not get acting on behalf of orgs", e);
            }
        }
        return new ArrayList<>();
    }

    protected PKIIdentity getPKIIdentity(String userMrn, UserModel user, CloseableHttpClient httpClient) {
        if (serverRoot != null) {
            if (httpClient == null) {
                log.error("Could not build http client");
                return null;
            }
            String uri = servicePath + userMrn + "/pki-identity";
            HttpGet get = new HttpGet(uri);
            try (CloseableHttpResponse response = httpClient.execute(get)) {
                int status = response.getCode();
                HttpEntity entity = response.getEntity();
                if (status != 200) {
                    log.error("Getting PKIIdentity of user failed");
                } else {
                    String json = getContent(entity);
                    PKIIdentity pkiIdentity = JsonSerialization.readValue(json, PKIIdentity.class);
                    if (pkiIdentity != null) {
                        user.setAttribute("uid", Collections.singletonList(pkiIdentity.getDn()));
                        user.setAttribute("subsidiary_mrn", Collections.singletonList(pkiIdentity.getMrnSubsidiary()));
                        user.setAttribute("mms_url", Collections.singletonList(pkiIdentity.getHomeMmsUrl()));
                    }
                    return pkiIdentity;
                }
            } catch (IOException e) {
                log.error("Could not get PKIIdentity of user", e);
            }
        }
        return null;
    }

    protected void sendUserUpdate(User user, String orgMrn, String orgName, String orgAddress, CloseableHttpClient client) {
        if (client == null) {
            return;
        }
        String uri = serverRoot + "/x509/api/org/" + orgMrn + "/user-sync/";
        if (orgName != null && orgAddress != null) {
            uri += "?org-name=" + URLEncoder.encode(orgName, StandardCharsets.UTF_8) + "&org-address=" + URLEncoder.encode(orgAddress, StandardCharsets.UTF_8);
        }
        HttpPost post = new HttpPost(uri);
        CloseableHttpResponse response = null;
        try {
            String serializedUser = JsonSerialization.writeValueAsString(user);
            StringEntity input = new StringEntity(serializedUser, ContentType.APPLICATION_JSON);
            post.setEntity(input);
            log.debug("user json: " + serializedUser);
            log.debug("uri: " + uri);
            response = client.execute(post);
            int status = response.getCode();
            HttpEntity entity = response.getEntity();
            if (status != 200) {
                String json = getContent(entity);
                log.errorf("User sync failed. Bad status: %s response: %s", status, json);
            } else {
                log.info("User sync'ed!");
            }
        } catch (IOException e) {
            log.error("Could not send user update request", e);
        } finally {
            try {
                if (response != null) {
                    response.close();
                }
            } catch (IOException e) {
                log.error("Could not close user update response", e);
            }
        }
    }

    protected String getContent(HttpEntity entity) {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        try {
            entity.writeTo(os);
        } catch (IOException e) {
            log.error("Could not get content", e);
            throw new McpException(e);
        }
        return os.toString();
    }

    protected CloseableHttpClient buildHttpClient() {
        log.debug("keystore path: " + keystorePath);
        log.debug("truststorePath path: " + truststorePath);
        KeyStore keyStore;
        KeyStore trustStore = null;
        FileInputStream instreamTruststore = null;
        try (FileInputStream instreamKeystore = new FileInputStream(keystorePath)) {
            keyStore = KeyStore.getInstance("jks");
            keyStore.load(instreamKeystore, keystorePassword.toCharArray());
            if (truststorePath != null && !truststorePath.isEmpty()) {
                trustStore = KeyStore.getInstance("jks");
                instreamTruststore = new FileInputStream(truststorePath);
                trustStore.load(instreamTruststore, truststorePassword.toCharArray());
            }
        } catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
            log.error("Could not load keystore or truststore", e);
            throw new McpException(e);
        } finally {
            try {
                if (instreamTruststore != null) {
                    instreamTruststore.close();
                }
            } catch (IOException e) {
                log.error("Could not close truststore", e);
            }
        }

        // Trust own CA and all self-signed certs
        SSLContext sslcontext;
        try {
            SSLContextBuilder sslContextBuilder = SSLContexts.custom();
            // If you have a trust store - should only be needed when the site we contact use self-signed certificates.
            if (trustStore != null) {
                sslContextBuilder.loadTrustMaterial(trustStore, new TrustSelfSignedStrategy());
            }
            sslContextBuilder.loadKeyMaterial(keyStore, keystorePassword.toCharArray());
            sslcontext = sslContextBuilder.build();
        } catch (KeyManagementException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException e) {
            log.error("Could not build ssl context", e);
            throw new McpException(e);
        }
        SSLConnectionSocketFactoryBuilder sslConnectionSocketFactoryBuilder = SSLConnectionSocketFactoryBuilder.create()
                .setSslContext(sslcontext)
                .setTlsVersions(TLS.V_1_2, TLS.V_1_3);
        if (trustStore != null) {
            sslConnectionSocketFactoryBuilder.setHostnameVerifier(new NoopHostnameVerifier());
        }

        SSLConnectionSocketFactory sslSocketFactory = sslConnectionSocketFactoryBuilder.build();
        HttpClientConnectionManager connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
                .setSSLSocketFactory(sslSocketFactory)
                .build();
        return HttpClients.custom().setConnectionManager(connectionManager).build();
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        // not needed
        
    }

}
