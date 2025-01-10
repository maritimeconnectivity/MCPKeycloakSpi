[![Java CI with Maven](https://github.com/maritimeconnectivity/MCPKeycloakSpi/actions/workflows/maven.yml/badge.svg)](https://github.com/maritimeconnectivity/MCPKeycloakSpi/actions/workflows/maven.yml)

# Maritime Connectivity Platform implementation of Keycloak SPI

Keycloak has a series of Service Provider Interfaces (SPI) that allows for adding new functionality where needed. For
Keycloak to work in as the MCP Identity Broker the SPI mentioned below has been implemented.

For setup please refer to
the [MIR deployment guidelines](https://github.com/maritimeconnectivity/IdentityRegistry/blob/master/setup/guide/MIR_setup.pdf)
as well as the information below.

## MCP Event Listener

This is an implementation of a Keycloak Event Listener, implementing the Event Listener SPI as
described [here](https://www.keycloak.org/docs/latest/server_development/index.html#_events).

This is used to keep the user database in the MCP Identity Registry API in sync with information fetched during login
using the MCP ID Broker. When a user logs in this EventListener will make a call to a REST webservice which includes the
user information passed from the users Identity Provider. The webservice call uses a certificate to authenticate itself
against the API. The Event Listener is setup by adding
`mcp-identityregistry-keycloak-spi-latest-jar-with-dependencies.jar` in the `providers/` folder.
The Event Listener can be configured with the following environmental variables:

| Variable                                                      | Description                                                                                                                                       |
|---------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| KC_SPI_EVENTS_LISTENER_MCP_EVENT_LISTENER_SERVER_ROOT         | The root URL to the MIR API                                                                                                                       |
| KC_SPI_EVENTS_LISTENER_MCP_EVENT_LISTENER_KEYSTORE_PATH       | Path to a keystore that is used to authenticate to the MIR API                                                                                    |
| KC_SPI_EVENTS_LISTENER_MCP_EVENT_LISTENER_KEYSTORE_PASSWORD   | The password for the keystore that is used to authenticate to the MIR API                                                                         |
| KC_SPI_EVENTS_LISTENER_MCP_EVENT_LISTENER_TRUSTSTORE_PATH     | Path to a custom truststore. Should only be set if the MIR API is using a TLS certificate that cannot be verified against the built-in truststore |
| KC_SPI_EVENTS_LISTENER_MCP_EVENT_LISTENER_TRUSTSTORE_PASSWORD | Password to the custom truststore that is defined by the previous variable. Should only be set if the previous variable is set                    |
| KC_SPI_EVENTS_LISTENER_MCP_EVENT_LISTENER_IDP_NOT_TO_SYNC     | Comma separated list of identity providers that should not be synchronized on login                                                               |
| KC_SPI_AUTHENTICATOR_CERTIFICATE_CLIENT_CERT_HEADER           | The HTTP header that the client certificate is put into by the reverse proxy. The default value is "X-Client-Certificate"                         |

The keystore holds the certificate to authenticate the event listener, while the truststore holds the trusted
certificate of the Identity Registry API. The truststore should only be needed in test setups where self-signed
certificates are used.

After doing the setup as described above, go into the admin console in Keycloak and go to Events in the left side menu.
Go to the Config tab, add mcp-event-listener to the Event Listeners and click Save.

## Authenticator using X.509 certificates

The purpose of this SPI is to allow users to authenticate using X.509 certificates. This is meant as a "bridge" where a
certificate can be converted into a OpenId Connect token.

The Authenticator is setup by adding the jar in the `providers/` folder.

For configuration, an authentication flow should be setup with a single step where the type is `Certificates` and the
requirement is `Required`.
