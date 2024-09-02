/* Copyright 2017 Danish Maritime Authority.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package net.maritimeconnectivity.identityregistry.keycloak.spi.eventprovider;

import net.maritimeconnectivity.pki.PKIIdentity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;


class MCPEventListenerProviderTest {

    private Event mockedEvent;

    private KeycloakSession mockedKeycloakSession;

    private RealmProvider mockedRealmProvider;

    private RealmModel mockedRealmModel;

    private UserModel mockedUserModel;

    private UserProvider mockedUserProvider;

    private MCPEventListenerProvider mcpEventListenerProvider;

    @BeforeEach
    void setUp() {
        this.mockedKeycloakSession = mock(KeycloakSession.class);
        this.mockedRealmProvider = mock(RealmProvider.class);
        this.mockedRealmModel = mock(RealmModel.class);
        this.mockedUserProvider = mock(UserProvider.class);
        this.mockedUserModel = mock(UserModel.class);

        given(this.mockedKeycloakSession.users()).willReturn(this.mockedUserProvider);
        given(this.mockedKeycloakSession.realms()).willReturn(this.mockedRealmProvider);
        given(this.mockedRealmProvider.getRealm(any())).willReturn(this.mockedRealmModel);
        given(this.mockedUserProvider.getUserById(any(RealmModel.class), any(String.class))).willReturn(this.mockedUserModel);

        mockedEvent = mock(Event.class);
    }

    /**
     * Test with an unsupported login type
     */
    @Test
    void onEventUnsupportedType() {
        // Set an unsupported type that should result in no actions
        given(this.mockedEvent.getType()).willReturn(EventType.CLIENT_LOGIN);

        mcpEventListenerProvider = new MCPEventListenerProvider(null, null, "src/test/resources/keystore.jks", "changeit", null, null, null);
        mcpEventListenerProvider.onEvent(this.mockedEvent);

        verify(mockedEvent, times(1)).getType();
        verify(mockedEvent, times(0)).getDetails();
        verify(mockedEvent, times(0)).getRealmId();
    }

    /**
     * Test without an identity provider
     */
    @Test
    void onEventNoIdp() {
        // Set an supported type that should result in going past the first check
        given(this.mockedEvent.getType()).willReturn(EventType.LOGIN);

        mcpEventListenerProvider = new MCPEventListenerProvider(null, null, "src/test/resources/keystore.jks", "changeit", null, null, null);
        mcpEventListenerProvider.onEvent(this.mockedEvent);
        verify(mockedEvent, times(2)).getType();
        verify(mockedEvent, times(2)).getDetails();
        verify(mockedEvent, times(2)).getRealmId();
    }

    /**
     * Test that we skip on "blacklisted" IDPs
     */
    @Test
    void onEventSkipIdp() {
        // Set an supported type that should result in going past the first check
        given(this.mockedEvent.getType()).willReturn(EventType.LOGIN);
        // Insert an identity_provider "certificates"
        Map<String, String> details = new HashMap<>();
        details.put("identity_provider", "certificates");
        given(this.mockedEvent.getDetails()).willReturn(details);

        // Put "certificates" in the list of identity_providers that should be skipped.
        String[] noSyncIdps = new String[]{ "certificates" };

        mcpEventListenerProvider = new MCPEventListenerProvider(null, null, "src/test/resources/keystore.jks", "changeit", null, null, noSyncIdps);
        mcpEventListenerProvider.onEvent(this.mockedEvent);
        verify(mockedEvent, times(2)).getType();
        verify(mockedEvent, times(2)).getDetails();
        verify(mockedEvent, times(2)).getRealmId();
    }


    /**
     * Test that we actually works
     */
    @Test
    void onEvent() {
        // Set an supported type that should result in going past the first check
        given(this.mockedEvent.getType()).willReturn(EventType.LOGIN);
        given(this.mockedEvent.getRealmId()).willReturn("fake-realm-id");
        given(this.mockedEvent.getUserId()).willReturn("fake-user-id");
        // Insert an identity_provider "dma"
        Map<String, String> details = new HashMap<>();
        details.put("identity_provider", "dma");
        given(this.mockedEvent.getDetails()).willReturn(details);

        // Setup the mocked usermodel
        given(this.mockedUserModel.getEmail()).willReturn("thc@dma.dk");
        given(this.mockedUserModel.getFirstName()).willReturn("Thomas");
        given(this.mockedUserModel.getLastName()).willReturn("Christensen");
        given(this.mockedUserModel.getUsername()).willReturn("urn:mrn:mcl:user:dma:thc");
        Map<String, List<String>> attrs = new HashMap<>();
        attrs.put("org", Collections.singletonList("urn:mrn:mcl:org:dma"));
        attrs.put("mrn", Collections.singletonList("urn:mrn:mcl:user:dma:thc"));
        attrs.put("permissions", Collections.singletonList("NONE"));
        given(this.mockedUserModel.getAttributes()).willReturn(attrs);

        // Put "certificates" in the list of identity_providers that should be skipped.
        String[] noSyncIdps = new String[]{ "certificates" };

        // Create a spy version of the event listener
        mcpEventListenerProvider = spy(new MCPEventListenerProvider(mockedKeycloakSession, "", "src/test/resources/keystore.jks", "changeit", null, null, noSyncIdps));

        // Make sure the sendUserUpdate method does nothing
        doNothing().when(mcpEventListenerProvider).sendUserUpdate(any(), any(), any(), any());
        doNothing().when(mcpEventListenerProvider).getUserRolesAndActingOnBehalfOf(any(), any(), any());
        PKIIdentity mockPKIIdentity = spy(new PKIIdentity());
        given(mcpEventListenerProvider.getPKIIdentity(any(), any())).willReturn(mockPKIIdentity);

        // Call onEvent
        mcpEventListenerProvider.onEvent(this.mockedEvent);

        // Verify the execution went as planned
        verify(mockedEvent, times(2)).getType();
        verify(mockedEvent, times(2)).getDetails();
        verify(mockedEvent, times(4)).getRealmId();
        verify(mockedUserModel, times(1)).getEmail();
        verify(mcpEventListenerProvider, times(1)).sendUserUpdate(any(), eq("urn:mrn:mcl:org:dma"), eq(null), eq(null));
        verify(mcpEventListenerProvider, times(2)).getPKIIdentity(eq("urn:mrn:mcl:user:dma:thc"), any());
    }

}
