# Maritime Cloud implementation of Keycloak SPI

Keycloak has a series of Service Provider Interfaces (SPI) that allows for adding new functionality where needed. For Keycloak to work in as the Maritime Cloud Identity Broker the SPI mentioned below has been implemented.

## Maritime Cloud Event Listener
This is an implementation of a Keycloak EventListener, implementing the EventListener SPI as described [here](http://keycloak.github.io/docs/userguide/keycloak-server/html/providers.html).

This is used to keep the user database in the MaritimeCloud Identity Registry API in sync with information fetched during login using the MaritimeCloud ID Broker. When a user logs in this EventListener will make a call to a REST webservice which includes the user information passed from the users Identity Provider. The webservice call uses a certificate to authenticate itself against the API. The EventListener is setup by adding the jar in the `providers/` folder. In `standalone/configuration/keycloak-server.json` the following section is added (change it as needed):

```json
	"eventsListener": {
		"mc-event-listener" : {
			"server-root": "https://localhost:8443",
			"keystore-path": "idbroker-updater.jks",
			"keystore-password": "changeit",
			"truststore-path": "mc-truststore.jks",
			"truststore-password": "changeit"
		}
	},
```

The keystore holds the certificate to authenticate the eventlistener, while the truststore holds the trusted certificate of the Identity Registry API. The truststore should only be needed in test setups where self-signed certificates are used.

After doing the setup as described above, go into the admin console in Keycloak and go to Events in the left side menu. Go to the Config tab, add mc-event-listener to the Event Listeners and click Save.


## Authenticator for updating without prompt
This SPI is implemented in order to allow copying of user data from IDPs to the local Keycloak without prompting the user for review or trying to link existing accounts.

The authenticator is available in Keycloaks Authentication Flow configuration screen when adding new execution as "Update user without prompting for review".
