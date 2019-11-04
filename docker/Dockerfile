# Run like this:
# docker run --name keycloak -v /path/to/config-directory/on/machine:/mc-eventprovider-conf -e DB_DATABASE=kcdb -e DB_USERNAME=kcuser -e DB_PASSWORD=kcpassword -e DB_PORT=3306 -e DB_ADDR=localhost dmadk/keycloak-mysql-mc-ha:latest
#
FROM jboss/keycloak:7.0.1

# Change the standalone.xml to support https-proxy-forwarding and include custom SPI settings
#ADD proxy-forward.xslt /opt/jboss/keycloak/
#RUN java -jar /usr/share/java/saxon.jar -s:/opt/jboss/keycloak/standalone/configuration/standalone.xml -xsl:/opt/jboss/keycloak/proxy-forward.xslt -o:/opt/jboss/keycloak/standalone/configuration/standalone.xml; \
#	java -jar /usr/share/java/saxon.jar -s:/opt/jboss/keycloak/standalone/configuration/standalone-ha.xml -xsl:/opt/jboss/keycloak/proxy-forward.xslt -o:/opt/jboss/keycloak/standalone/configuration/standalone-ha.xml; \
#	rm /opt/jboss/keycloak/proxy-forward.xslt
# Overwrite the standard entrypoint file and set host ip and hostname to env variables
ADD docker-entrypoint.sh /opt/jboss/tools/

#ADD JDBC_PING.cli /opt/jboss/tools/cli/jgroups/discovery/

# Overwrite module conf for jgroup to include mysql driver as dependency
#ADD module.xml keycloak/modules/system/layers/base/org/jgroups/main/module.xml

# Add the maritime cloud theme
ADD themes /opt/jboss/keycloak/themes/

# Set locales for image to support UTF-8
#ENV LANG='en_US.UTF-8' LANGUAGE='en_US:en' LC_ALL='en_US.UTF-8'

ENV DB_VENDOR mysql

USER root
RUN mkdir -p /mc-eventprovider-conf

USER jboss
ADD mc-identityregistry-keycloak-spi-latest-jar-with-dependencies.jar /opt/jboss/keycloak/providers/

# Overwrite the standard CMD
CMD ["-c", "standalone-ha.xml"]

# Set the environmental variables
ENV DB_DATABASE keycloak
ENV DB_USER keycloak
ENV DB_PASSWORD password
ENV DB_ADDR localhost
ENV DB_PORT 3306
ENV JGROUPS_DISCOVERY_PROTOCOL JDBC_PING
ENV JGROUPS_DISCOVERY_PROPERTIES datasource_jndi_name=java:jboss/datasources/KeycloakDS
ENV PROXY_ADDRESS_FORWARDING true

ENV MC_IDREG_SERVER_ROOT https://localhost
ENV SYNC_KEYSTORE_PATH /mc-eventprovider-conf/idbroker-updater.jks
ENV SYNC_KEYSTORE_PASSWORD changeit
ENV SYNC_TRUSTSTORE_PATH /mc-eventprovider-conf/mc-truststore.jks
ENV SYNC_TRUSTSTORE_PASSWORD changeit
ENV NOSYNC_IDPS certificates,projecttestusers
