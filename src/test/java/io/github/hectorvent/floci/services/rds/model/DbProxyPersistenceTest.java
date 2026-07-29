package io.github.hectorvent.floci.services.rds.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class DbProxyPersistenceTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void computedEndpointIsNotPersisted() throws Exception {
        DbProxy proxy = new DbProxy();
        proxy.setDbProxyName("app-proxy");
        proxy.setEndpointHost("127.0.0.1");

        String persisted = objectMapper.writeValueAsString(proxy);

        assertFalse(objectMapper.readTree(persisted).has("endpoint"));
        assertEquals("127.0.0.1",
                objectMapper.readValue(persisted, DbProxy.class).getEndpoint());
    }

    @Test
    void legacyComputedEndpointIsIgnoredDuringRestore() throws Exception {
        DbProxy restored = objectMapper.readValue("""
                {
                  "dbProxyName": "app-proxy",
                  "endpointHost": "127.0.0.1",
                  "endpoint": "127.0.0.1"
                }
                """, DbProxy.class);

        assertEquals("127.0.0.1", restored.getEndpoint());
    }
}
