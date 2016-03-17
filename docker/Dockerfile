# Run like this:
# docker run --name keycloak -v /path/to/config-directory/on/machine:/mc-eventprovider-conf -e MYSQL_PORT_3306_TCP_ADDR=localhost -e MYSQL_DATABASE=kcdb -e MYSQL_USER=kcuser -e MYSQL_PASSWORD=kcpassword jboss/keycloak-mysql
# 
# A customized patch to the conf file (mc-identityregistry-keycloak-eventprovider-conf.patch) must be available
# in the folder mounted to /mc-eventprovider-conf. A trust and keystore must also be placed in the folder. Make
# sure the values in the patch matches the 
FROM jboss/keycloak-mysql:latest

RUN mkdir -p /mc-eventprovider-conf
ADD mc-identityregistry-keycloak-eventprovider-*.jar providers/
RUN patch -i /mc-eventprovider-conf/mc-identityregistry-keycloak-eventprovider-conf.patch -p0
