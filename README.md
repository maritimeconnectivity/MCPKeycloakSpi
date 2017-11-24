[![Build Status](https://travis-ci.org/MaritimeCloud/MCPKeycloakSpi.svg?branch=master)](https://travis-ci.org/MaritimeCloud/MCPKeycloakSpi)

# Maritime Connectivity Platform implementation of Keycloak SPI

Keycloak has a series of Service Provider Interfaces (SPI) that allows for adding new functionality where needed. For Keycloak to work in as the MCP Identity Broker the SPI mentioned below has been implemented.

## MCP Event Listener
This is an implementation of a Keycloak EventListener, implementing the EventListener SPI as described [here](https://keycloak.gitbooks.io/documentation/server_development/topics/providers.html).

This is used to keep the user database in the MCP Identity Registry API in sync with information fetched during login using the MCP ID Broker. When a user logs in this EventListener will make a call to a REST webservice which includes the user information passed from the users Identity Provider. The webservice call uses a certificate to authenticate itself against the API. The EventListener is setup by adding `mc-identityregistry-keycloak-spi-latest-jar-with-dependencies.jar` in the `providers/` folder. In `standalone/configuration/standalone.xml` the following section is added in the /server/provider/subsystem section:

```xml
 <spi name="eventsListener">
	<provider name="mc-event-listener" enabled="true">
		<properties>
			<property name="server-root" value="${env.MC_IDREG_SERVER_ROOT:https://localhost}"/>
			<property name="keystore-path" value="${env.SYNC_KEYSTORE_PATH:/mc-eventprovider-conf/idbroker-updater.jks}"/>
			<property name="keystore-password" value="${env.SYNC_KEYSTORE_PASSWORD:changeit}"/>
			<property name="truststore-path" value="${env.SYNC_TRUSTSTORE_PATH:}"/>
			<property name="truststore-password" value="${env.SYNC_TRUSTSTORE_PASSWORD:}"/>
			<property name="idp-not-to-sync" value="${env.NOSYNC_IDPS:certificates,projecttestusers}"/>
		</properties>
	</provider>
 </spi>
```

Either set the environmental variables mentioned in the xml before running Keycloak, rely on the default values or hardcode the values into the xml.

The keystore holds the certificate to authenticate the eventlistener, while the truststore holds the trusted certificate of the Identity Registry API. The truststore should only be needed in test setups where self-signed certificates are used.

After doing the setup as described above, go into the admin console in Keycloak and go to Events in the left side menu. Go to the Config tab, add mc-event-listener to the Event Listeners and click Save.


## Authenticator using X.509 certificates

The purpose of this SPI is to allow users to authenticate using X.509 certificates. This is meant as a "bridge" where a certificate can be converted into a OpenId Connect token.

The Authenticator is setup by adding the jar in the `providers/` folder. In `standalone/configuration/standalone.xml` the following section is added in the /server/provider/subsystem section:

```xml
<spi name="authenticator">
	<provider name="certificate" enabled="true">
		<properties>
			<property name="truststore-path" value="${env.CERT_TRUSTSTORE_PATH:/mc-eventprovider-conf/mc-truststore.jks}"/>
			<property name="truststore-password" value="${env.CERT_TRUSTSTORE_PATH:changeit}"/>
		</properties>
	</provider>
</spi>
```

Either set the environmental variables mentioned in the xml before running Keycloak, rely on the default values or hardcode the values into the xml. The truststore should contain the MCP Identity Registry Root certificate so that client certificates that are issued by it are trusted by the authenticator.


## Authenticator for updating without prompt (JavaScript)

This SPI is implemented in order to allow copying of user data from IDPs to the local Keycloak without prompting the user for review or trying to link existing accounts. It also deletes any existing user with a conflicting email-address. This is done to workaround a current limitation in Keycloak where 2 users cannot share an email address.

The authenticator is implemented in JavaScript (available in the "javascript-authenticator" folder) and must be manually added in Keycloaks Authentication Flow configuration screen as a Script Authenticator (insert using copy/paste). The authenticator should be the only execution in its flow.

