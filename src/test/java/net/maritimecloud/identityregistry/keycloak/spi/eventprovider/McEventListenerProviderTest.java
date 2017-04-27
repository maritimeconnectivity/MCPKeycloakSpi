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
package net.maritimecloud.identityregistry.keycloak.spi.eventprovider;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;


class McEventListenerProviderTest {

    private Event mockedEvent;

    private McEventListenerProvider mcEventListenerProvider;

    @BeforeEach
    void setUp() {
        mockedEvent = mock(Event.class);
    }

    @Test
    void onEventUnsupportedType() {
        // Set an unsupported type that should result in null being returned
        given(this.mockedEvent.getType()).willReturn(EventType.CLIENT_LOGIN);

        mcEventListenerProvider = new McEventListenerProvider(null, null, null, null, null, null, null);
        mcEventListenerProvider.onEvent(this.mockedEvent);
    }

}