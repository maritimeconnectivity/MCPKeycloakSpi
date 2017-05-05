#!/bin/bash

export EXTERNAL_HOSTNAME=$(curl -s 169.254.169.254/latest/meta-data/local-hostname)
export EXTERNAL_HOST_IP=$(curl -s 169.254.169.254/latest/meta-data/local-ipv4)

if [ $KEYCLOAK_USER ] && [ $KEYCLOAK_PASSWORD ]; then
    keycloak/bin/add-user-keycloak.sh --user $KEYCLOAK_USER --password $KEYCLOAK_PASSWORD
fi

exec /opt/jboss/keycloak/bin/standalone.sh -Djboss.node.name=$HOSTNAME -Djgroups.bind_addr=global -b $HOSTNAME $@
exit $?
