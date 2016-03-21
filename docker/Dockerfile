# Run like this:
# docker run --name keycloak -v /path/to/config-directory/on/machine:/mc-eventprovider-conf -e MYSQL_DATABASE=kcdb -e MYSQL_USERNAME=kcuser -e MYSQL_PASSWORD=kcpassword -e MYSQL_PORT_3306_TCP_PORT=3306 -e MYSQL_PORT_3306_TCP_ADDR=localhost keycloak-mysql-mc:latest
# 
# A custom keycloak-server.json conf file must be available in the folder mounted to /mc-eventprovider-conf.
# A trust and keystore must also be placed in the folder.
FROM jboss/keycloak-mysql:latest

USER root
RUN mkdir -p /mc-eventprovider-conf
# Hack to copy the customized keycloak-server.json to keycloak at runtime
RUN sed -i '2icp /mc-eventprovider-conf/keycloak-server.json /opt/jboss/keycloak/standalone/configuration/' /opt/jboss/docker-entrypoint.sh

USER jboss
RUN cd  /opt/jboss/keycloak/providers; curl -O https://dma.ci.cloudbees.com/view/MaritimeCloud/job/MaritimeCloudEventProvider/lastSuccessfulBuild/artifact/target/mc-identityregistry-keycloak-eventprovider-latest.jar

ENV MYSQL_DATABASE keycloak
ENV MYSQL_USERNAME keycloak
ENV MYSQL_PASSWORD password
ENV MYSQL_PORT_3306_TCP_ADDR localhost
ENV MYSQL_PORT_3306_TCP_PORT 3306
