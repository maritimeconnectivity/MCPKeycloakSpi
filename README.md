# Maritime Cloud Event Listener (for use with Keycloak)
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
