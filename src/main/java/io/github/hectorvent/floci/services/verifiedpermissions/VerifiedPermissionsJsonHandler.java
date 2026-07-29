package io.github.hectorvent.floci.services.verifiedpermissions;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.AwsErrorResponse;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;

@ApplicationScoped
public class VerifiedPermissionsJsonHandler {

    private final ObjectMapper objectMapper;
    private final VerifiedPermissionsService service;

    @Inject
    public VerifiedPermissionsJsonHandler(ObjectMapper objectMapper, VerifiedPermissionsService service) {
        this.objectMapper = objectMapper;
        this.service = service;
    }

    public Response handle(String action, JsonNode request) {
        return switch (action) {
            case "IsAuthorized" -> handleIsAuthorized(request);
            default -> Response.status(400)
                    .entity(new AwsErrorResponse(
                            "UnknownOperationException",
                            "Unknown operation: VerifiedPermissions." + action))
                    .build();
        };
    }

    private Response handleIsAuthorized(JsonNode request) {
        service.authorize(
                request.path("policyStoreId").asText(null),
                request.get("principal"),
                request.get("action"),
                request.get("resource"));

        ObjectNode response = objectMapper.createObjectNode();
        response.put("decision", "ALLOW");
        response.putArray("determiningPolicies");
        response.putArray("errors");
        return Response.ok(response).build();
    }
}
