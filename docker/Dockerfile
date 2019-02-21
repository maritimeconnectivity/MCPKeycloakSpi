# Run like this:
# docker run --name keycloak -v /path/to/config-directory/on/machine:/mc-eventprovider-conf -e MYSQL_DATABASE=kcdb -e MYSQL_USERNAME=kcuser -e MYSQL_PASSWORD=kcpassword -e MYSQL_PORT_3306_TCP_PORT=3306 -e MYSQL_PORT_3306_TCP_ADDR=localhost keycloak-mysql-mc:latest
# 
# A custom keycloak-server.json conf file must be available in the folder mounted to /mc-eventprovider-conf.
# A trust and keystore must also be placed in the folder.
FROM jboss/keycloak:4.8.3.Final

# Change the standalone.xml to support https-proxy-forwarding and include custom SPI settings
ADD proxy-forward.xslt /opt/jboss/keycloak/
ADD jgroup.xslt /opt/jboss/keycloak/
RUN java -jar /usr/share/java/saxon.jar -s:/opt/jboss/keycloak/standalone/configuration/standalone.xml -xsl:/opt/jboss/keycloak/proxy-forward.xslt -o:/opt/jboss/keycloak/standalone/configuration/standalone.xml; \
	java -jar /usr/share/java/saxon.jar -s:/opt/jboss/keycloak/standalone/configuration/standalone-ha.xml -xsl:/opt/jboss/keycloak/proxy-forward.xslt -o:/opt/jboss/keycloak/standalone/configuration/standalone-ha.xml; \
	java -jar /usr/share/java/saxon.jar -s:/opt/jboss/keycloak/standalone/configuration/standalone-ha.xml -xsl:/opt/jboss/keycloak/jgroup.xslt -o:/opt/jboss/keycloak/standalone/configuration/standalone-ha.xml; \
	rm /opt/jboss/keycloak/proxy-forward.xslt; \
	rm /opt/jboss/keycloak/jgroup.xslt

# DISABLE FOR NON-DISTRIBUTED BUILD!
# Overwrite the standard entrypoint file and set host ip and hostname to env variables 
ADD docker-entrypoint.sh /opt/jboss/tools/

# DISABLE FOR NON-DISTRIBUTED BUILD!
# Overwrite module conf for jgroup to include mysql driver as dependency
ADD module.xml keycloak/modules/system/layers/base/org/jgroups/main/module.xml

# Add the maritime cloud theme
ADD themes /opt/jboss/keycloak/themes/

# Set locales for image to support UTF-8
ENV LANG='en_US.UTF-8' LANGUAGE='en_US:en' LC_ALL='en_US.UTF-8'

ENV DB_VENDOR mysql

USER root
RUN mkdir -p /mc-eventprovider-conf

USER jboss
ADD mc-identityregistry-keycloak-spi-latest-jar-with-dependencies.jar /opt/jboss/keycloak/providers/

# DISABLE FOR NON-DISTRIBUTED BUILD!
# Overwrite the standard CMD
CMD ["-c", "standalone-ha.xml"]

# Set the environmental variables
ENV MYSQL_DATABASE keycloak
ENV MYSQL_USERNAME keycloak
ENV MYSQL_PASSWORD password
ENV MYSQL_PORT_3306_TCP_ADDR localhost
ENV MYSQL_PORT_3306_TCP_PORT 3306

ENV MC_IDREG_SERVER_ROOT https://localhost
ENV SYNC_KEYSTORE_PATH /mc-eventprovider-conf/idbroker-updater.jks
ENV SYNC_KEYSTORE_PASSWORD changeit
ENV SYNC_TRUSTSTORE_PATH /mc-eventprovider-conf/mc-truststore.jks
ENV SYNC_TRUSTSTORE_PASSWORD changeit
ENV NOSYNC_IDPS certificates,projecttestusers
