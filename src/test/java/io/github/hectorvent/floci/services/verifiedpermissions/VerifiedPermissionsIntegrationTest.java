package io.github.hectorvent.floci.services.verifiedpermissions;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;

@QuarkusTest
class VerifiedPermissionsIntegrationTest {

    private static final String CONTENT_TYPE = "application/x-amz-json-1.0";
    private static final String AUTH_HEADER =
            "AWS4-HMAC-SHA256 Credential=AKID/20260101/us-east-1/verifiedpermissions/aws4_request";

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void isAuthorized_localPolicyStore_returnsAllowDecision() {
        given()
                .contentType(CONTENT_TYPE)
                .header("X-Amz-Target", "VerifiedPermissions.IsAuthorized")
                .header("Authorization", AUTH_HEADER)
                .body("""
                        {
                          "policyStoreId": "local-policy-store",
                          "principal": {"entityType": "Core::User", "entityId": "user-alpha"},
                          "action": {"actionType": "Accounts::Action", "actionId": "ListAccounts"},
                          "resource": {"entityType": "Accounts::Account", "entityId": "*"}
                        }
                        """)
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("decision", equalTo("ALLOW"))
                .body("determiningPolicies", empty())
                .body("errors", empty());
    }

    @Test
    void isAuthorized_unknownPolicyStore_returnsResourceNotFound() {
        given()
                .contentType(CONTENT_TYPE)
                .header("X-Amz-Target", "VerifiedPermissions.IsAuthorized")
                .header("Authorization", AUTH_HEADER)
                .body("""
                        {
                          "policyStoreId": "unknown-store",
                          "principal": {"entityType": "Core::User", "entityId": "user-alpha"},
                          "action": {"actionType": "Accounts::Action", "actionId": "ListAccounts"},
                          "resource": {"entityType": "Accounts::Account", "entityId": "*"}
                        }
                        """)
        .when()
                .post("/")
        .then()
                .statusCode(400)
                .body("__type", equalTo("ResourceNotFoundException"));
    }

    @Test
    void isAuthorized_missingRequiredIdentifier_returnsValidationError() {
        given()
                .contentType(CONTENT_TYPE)
                .header("X-Amz-Target", "VerifiedPermissions.IsAuthorized")
                .header("Authorization", AUTH_HEADER)
                .body("""
                        {
                          "policyStoreId": "local-policy-store",
                          "principal": {"entityType": "Core::User"},
                          "action": {"actionType": "Accounts::Action", "actionId": "ListAccounts"},
                          "resource": {"entityType": "Accounts::Account", "entityId": "*"}
                        }
                        """)
        .when()
                .post("/")
        .then()
                .statusCode(400)
                .body("__type", equalTo("ValidationException"));
    }

    @Test
    void unknownOperation_returnsAwsUnknownOperationError() {
        given()
                .contentType(CONTENT_TYPE)
                .header("X-Amz-Target", "VerifiedPermissions.NotAnOperation")
                .header("Authorization", AUTH_HEADER)
                .body("{}")
        .when()
                .post("/")
        .then()
                .statusCode(400)
                .body("__type", equalTo("UnknownOperationException"));
    }
}
