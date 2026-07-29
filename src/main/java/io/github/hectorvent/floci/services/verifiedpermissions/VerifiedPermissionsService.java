package io.github.hectorvent.floci.services.verifiedpermissions;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.hectorvent.floci.core.common.AwsException;
import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class VerifiedPermissionsService {

    static final String LOCAL_POLICY_STORE_ID = "local-policy-store";

    public void authorize(String policyStoreId, JsonNode principal, JsonNode action, JsonNode resource) {
        requireNonBlank(policyStoreId, "policyStoreId");
        requireEntityIdentifier(principal, "principal", "entityType", "entityId");
        requireEntityIdentifier(action, "action", "actionType", "actionId");
        requireEntityIdentifier(resource, "resource", "entityType", "entityId");

        if (!LOCAL_POLICY_STORE_ID.equals(policyStoreId)) {
            throw new AwsException(
                    "ResourceNotFoundException",
                    "Policy store " + policyStoreId + " was not found.",
                    400);
        }
    }

    private static void requireEntityIdentifier(
            JsonNode identifier,
            String field,
            String typeField,
            String idField) {
        if (identifier == null || !identifier.isObject()) {
            throw validationException(field + " is required.");
        }
        requireNonBlank(identifier.path(typeField).asText(null), field + "." + typeField);
        requireNonBlank(identifier.path(idField).asText(null), field + "." + idField);
    }

    private static void requireNonBlank(String value, String field) {
        if (value == null || value.isBlank()) {
            throw validationException(field + " is required.");
        }
    }

    private static AwsException validationException(String message) {
        return new AwsException("ValidationException", message, 400);
    }
}
