# Run like this:
# docker run --name keycloak -v /path/to/config-directory/on/machine:/mc-eventprovider-conf -e DB_DATABASE=kcdb -e DB_USERNAME=kcuser -e DB_PASSWORD=kcpassword -e DB_PORT=3306 -e DB_ADDR=localhost dmadk/keycloak-mysql-mc-ha:latest
#
FROM quay.io/keycloak/keycloak:20.0.0

# Set the environmental variables
ENV KC_DB postgres
ENV KC_DB_URL jdbc:postgresql://localhost/keycloak
ENV KC_DB_USERNAME keycloak
ENV KC_DB_PASSWORD password
ENV KC_PROXY edge
ENV KC_SPI_EVENTS_LISTENER_MCP_EVENT_LISTENER_SERVER_ROOT https://localhost
ENV KC_SPI_EVENTS_LISTENER_MCP_EVENT_LISTENER__KEYSTORE_PATH /mc-eventprovider-conf/idbroker-updater.jks
ENV KC_SPI_EVENTS_LISTENER_MCP_EVENT_LISTENER_KEYSTORE_PASSWORD changeit
ENV KC_SPI_EVENTS_LISTENER_MCP_EVENT_LISTENER_TRUSTSTORE_PATH ""
ENV KC_SPI_EVENTS_LISTENER_MCP_EVENT_LISTENER_TRUSTSTORE_PASSWORD ""
ENV KC_SPI_EVENTS_LISTENER_MCP_EVENT_LISTENER_IDP_NOT_TO_SYNC certificates,users
ENV MODE start-dev

# Add the mcp theme
ADD themes /opt/keycloak/themes/

USER root
RUN mkdir -p /mc-eventprovider-conf && chown 1000:0 /mc-eventprovider-conf

USER 1000
ADD mcp-identityregistry-keycloak-spi-latest.jar /opt/keycloak/providers/

RUN /opt/keycloak/bin/kc.sh build

CMD ["start", "--optimized"]
