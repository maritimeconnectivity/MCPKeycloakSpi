FROM quay.io/keycloak/keycloak:26.0.7

# Set the environmental variables
ENV KC_DB=postgres
ENV KC_DB_URL=jdbc:postgresql://localhost/keycloak
ENV KC_DB_USERNAME=keycloak
ENV KC_DB_PASSWORD=password
ENV KC_HTTP_ENABLED=true
ENV KC_PROXY_HEADERS=xforwarded
ENV KC_SPI_EVENTS_LISTENER_MCP_EVENT_LISTENER_SERVER_ROOT=https://localhost
ENV KC_SPI_EVENTS_LISTENER_MCP_EVENT_LISTENER_KEYSTORE_PATH=/mc-eventprovider-conf/idbroker-updater.jks
ENV KC_SPI_EVENTS_LISTENER_MCP_EVENT_LISTENER_KEYSTORE_PASSWORD=changeit
ENV KC_SPI_EVENTS_LISTENER_MCP_EVENT_LISTENER_TRUSTSTORE_PATH=""
ENV KC_SPI_EVENTS_LISTENER_MCP_EVENT_LISTENER_TRUSTSTORE_PASSWORD=""
ENV KC_SPI_EVENTS_LISTENER_MCP_EVENT_LISTENER_IDP_NOT_TO_SYNC=certificates,users
ENV KC_SPI_AUTHENTICATOR_CERTIFICATE_CLIENT_CERT_HEADER="X-Client-Certificate"
ENV KC_HTTP_RELATIVE_PATH=/auth

# Add the mcp theme
COPY themes /opt/keycloak/themes/

USER root
RUN mkdir -p /mc-eventprovider-conf && chown 1000:0 /mc-eventprovider-conf

USER 1000

# Download latest snapshot
ADD --chown=1000:0 'https://repo1.maven.org/maven2/net/maritimeconnectivity/pki/mcp-pki/1.3.0-RC2/mcp-pki-1.3.0-RC2.jar' /opt/keycloak/providers/mcp-pki.jar
COPY --chown=1000:0 mcp-identityregistry-keycloak-spi-latest.jar /opt/keycloak/providers/

RUN /opt/keycloak/bin/kc.sh build

CMD ["--spi-login-protocol-openid-connect-legacy-logout-redirect-uri=true", "start"]
