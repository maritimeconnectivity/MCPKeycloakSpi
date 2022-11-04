# Run like this:
# docker run --name keycloak -v /path/to/config-directory/on/machine:/mc-eventprovider-conf -e DB_DATABASE=kcdb -e DB_USERNAME=kcuser -e DB_PASSWORD=kcpassword -e DB_PORT=3306 -e DB_ADDR=localhost dmadk/keycloak-mysql-mc-ha:latest
#
FROM quay.io/keycloak/keycloak:20.0.0 as builder


# Add the mcp theme
ADD themes /opt/keycloak/themes/

USER root
RUN mkdir -p /mc-eventprovider-conf && chown 1000:0 /mc-eventprovider-conf

USER 1000
ADD mcp-identityregistry-keycloak-spi-latest.jar /opt/keycloak/providers/

RUN /opt/keycloak/bin/kc.sh build --spi-event-listener-provider-mc-event-listener-enabled=true --spi-authenticator-certificate=enabled

FROM quay.io/keycloak/keycloak:20.0.0

# Set the environmental variables
ENV KC_DB postgres
ENV KC_DB_URL jdbc:postgresql://localhost/keycloak
ENV KC_DB_USERNAME keycloak
ENV KC_DB_PASSWORD password
ENV KC_PROXY edge
ENV MC_IDREG_SERVER_ROOT https://localhost
ENV SYNC_KEYSTORE_PATH /mc-eventprovider-conf/idbroker-updater.jks
ENV SYNC_KEYSTORE_PASSWORD changeit
ENV SYNC_TRUSTSTORE_PATH ""
ENV SYNC_TRUSTSTORE_PASSWORD ""
ENV NOSYNC_IDPS certificates,users
ENV MODE start-dev

COPY --from=builder /opt/keycloak /opt/keycloak
COPY --from=builder /mc-eventprovider-conf /mc-eventprovider-conf

CMD ["$MODE", "--spi-event-listener-provider-mc-event-listener-server-root=$MC_IDREG_SERVER_ROOT", "--spi-event-listener-provider-mc-event-listener-keystore-path=$SYNC_KEYSTORE_PATH", "--spi-event-listener-provider-mc-event-listener-keystore-password=$SYNC_KEYSTORE_PASSWORD", "--spi-event-listener-provider-mc-event-listener-truststore-path=$SYNC_TRUSTSTORE_PATH", "--spi-event-listener-provider-mc-event-listener-truststore-password=$SYNC_TRUSTSTORE_PASSWORD", "--spi-event-listener-provider-mc-event-listener-idp-not-to-sync=$NOSYNC_IDPS"]
