FROM quay.io/keycloak/keycloak:23.0.5

# Set the environmental variables
ENV KC_DB postgres
ENV KC_DB_URL jdbc:postgresql://localhost/keycloak
ENV KC_DB_USERNAME keycloak
ENV KC_DB_PASSWORD password
ENV KC_PROXY edge
ENV KC_SPI_EVENTS_LISTENER_MCP_EVENT_LISTENER_SERVER_ROOT https://localhost
ENV KC_SPI_EVENTS_LISTENER_MCP_EVENT_LISTENER_KEYSTORE_PATH /mc-eventprovider-conf/idbroker-updater.jks
ENV KC_SPI_EVENTS_LISTENER_MCP_EVENT_LISTENER_KEYSTORE_PASSWORD changeit
ENV KC_SPI_EVENTS_LISTENER_MCP_EVENT_LISTENER_TRUSTSTORE_PATH ""
ENV KC_SPI_EVENTS_LISTENER_MCP_EVENT_LISTENER_TRUSTSTORE_PASSWORD ""
ENV KC_SPI_EVENTS_LISTENER_MCP_EVENT_LISTENER_IDP_NOT_TO_SYNC certificates,users
ENV KC_HTTP_RELATIVE_PATH /auth

# Add the mcp theme
ADD themes /opt/keycloak/themes/

USER root
RUN mkdir -p /mc-eventprovider-conf && chown 1000:0 /mc-eventprovider-conf

USER 1000

# Download latest snapshot
ADD --chown=1000:0 'https://oss.sonatype.org/service/local/artifact/maven/redirect?r=snapshots&g=net.maritimeconnectivity.pki&a=mcp-pki&v=1.3.0-SNAPSHOT' /opt/keycloak/providers/mcp-pki.jar
ADD --chown=1000:0 mcp-identityregistry-keycloak-spi-latest.jar /opt/keycloak/providers/

RUN /opt/keycloak/bin/kc.sh build

CMD ["--spi-login-protocol-openid-connect-legacy-logout-redirect-uri=true", "start"]
