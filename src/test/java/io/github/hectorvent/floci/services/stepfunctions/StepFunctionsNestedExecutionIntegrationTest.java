package io.github.hectorvent.floci.services.stepfunctions;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@QuarkusTest
class StepFunctionsNestedExecutionIntegrationTest {

    private static final String CONTENT_TYPE = "application/x-amz-json-1.0";
    private static final String ROLE_ARN = "arn:aws:iam::000000000000:role/test-role";

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void sync2WaitsForChildAndResultPathNullPreservesParentInput() throws Exception {
        String childDefinition = """
                {"StartAt":"Wait","States":{
                  "Wait":{"Type":"Wait","Seconds":1,"Next":"Done"},
                  "Done":{"Type":"Pass","Result":{"child":true},"End":true}}}
                """;
        String childArn = createStateMachine("nested-child-" + System.nanoTime(), childDefinition);

        String parentDefinition = """
                {"StartAt":"RunChild","States":{
                  "RunChild":{
                    "Type":"Task",
                    "Resource":"arn:aws:states:::states:startExecution.sync:2",
                    "Parameters":{
                      "StateMachineArn":"%s",
                      "Input.$":"$"
                    },
                    "ResultPath":null,
                    "End":true}}}
                """.formatted(childArn);
        String parentArn = createStateMachine("nested-parent-" + System.nanoTime(), parentDefinition);

        assertEquals("{\"request\":\"preserved\"}",
                run(parentArn, "{\"request\":\"preserved\"}"));
    }

    @Test
    void stoppedParentRemainsAbortedAfterNestedSyncChildCompletes() throws Exception {
        String childDefinition = """
                {"StartAt":"Wait","States":{
                  "Wait":{"Type":"Wait","Seconds":1,"Next":"Done"},
                  "Done":{"Type":"Pass","Result":{"child":true},"End":true}}}
                """;
        String childArn = createStateMachine("nested-stop-child-" + System.nanoTime(), childDefinition);
        String parentDefinition = """
                {"StartAt":"RunChild","States":{
                  "RunChild":{
                    "Type":"Task",
                    "Resource":"arn:aws:states:::states:startExecution.sync:2",
                    "Parameters":{"StateMachineArn":"%s","Input":{}},
                    "End":true}}}
                """.formatted(childArn);
        String parentArn = createStateMachine(
                "nested-stop-parent-" + System.nanoTime(), parentDefinition);
        String parentExecutionArn = startExecution(parentArn, "{}");

        waitForRunningExecution(childArn);
        given()
                .header("X-Amz-Target", "AWSStepFunctions.StopExecution")
                .contentType(CONTENT_TYPE)
                .body("{\"executionArn\":\"" + parentExecutionArn
                        + "\",\"cause\":\"test cancellation\"}")
            .when()
                .post("/")
            .then()
                .statusCode(200);

        Thread.sleep(1500);

        Response describe = describeExecution(parentExecutionArn);
        assertEquals("ABORTED", describe.jsonPath().getString("status"));

        Response history = given()
                .header("X-Amz-Target", "AWSStepFunctions.GetExecutionHistory")
                .contentType(CONTENT_TYPE)
                .body("{\"executionArn\":\"" + parentExecutionArn + "\"}")
            .when()
                .post("/");
        history.then().statusCode(200);
        java.util.List<String> eventTypes = history.jsonPath().getList("events.type");
        assertTrue(eventTypes.contains("ExecutionAborted"));
        assertFalse(eventTypes.contains("ExecutionSucceeded"));
    }

    private String createStateMachine(String name, String definition) {
        Response response = given()
                .header("X-Amz-Target", "AWSStepFunctions.CreateStateMachine")
                .contentType(CONTENT_TYPE)
                .body("{\"name\":\"" + name + "\",\"definition\":" + quote(definition)
                        + ",\"roleArn\":\"" + ROLE_ARN + "\"}")
                .when().post("/");
        response.then().statusCode(200);
        return response.jsonPath().getString("stateMachineArn");
    }

    private String run(String stateMachineArn, String input) throws InterruptedException {
        String executionArn = startExecution(stateMachineArn, input);

        for (int i = 0; i < 50; i++) {
            Response describe = describeExecution(executionArn);
            String status = describe.jsonPath().getString("status");
            if ("SUCCEEDED".equals(status)) {
                return describe.jsonPath().getString("output");
            }
            if ("FAILED".equals(status) || "ABORTED".equals(status)) {
                fail("Execution " + status + ": " + describe.body().asString());
            }
            Thread.sleep(100);
        }
        fail("Execution did not complete");
        return null;
    }

    private String startExecution(String stateMachineArn, String input) {
        Response start = given()
                .header("X-Amz-Target", "AWSStepFunctions.StartExecution")
                .contentType(CONTENT_TYPE)
                .body("{\"stateMachineArn\":\"" + stateMachineArn + "\",\"input\":" + quote(input) + "}")
            .when()
                .post("/");
        start.then().statusCode(200);
        return start.jsonPath().getString("executionArn");
    }

    private Response describeExecution(String executionArn) {
        Response describe = given()
                .header("X-Amz-Target", "AWSStepFunctions.DescribeExecution")
                .contentType(CONTENT_TYPE)
                .body("{\"executionArn\":\"" + executionArn + "\"}")
            .when()
                .post("/");
        describe.then().statusCode(200);
        return describe;
    }

    private void waitForRunningExecution(String stateMachineArn) throws InterruptedException {
        for (int i = 0; i < 50; i++) {
            Response list = given()
                    .header("X-Amz-Target", "AWSStepFunctions.ListExecutions")
                    .contentType(CONTENT_TYPE)
                    .body("{\"stateMachineArn\":\"" + stateMachineArn + "\"}")
                .when()
                    .post("/");
            list.then().statusCode(200);
            java.util.List<String> statuses = list.jsonPath().getList("executions.status");
            if (statuses.contains("RUNNING")) {
                return;
            }
            Thread.sleep(50);
        }
        fail("Nested execution did not enter RUNNING");
    }

    private static String quote(String raw) {
        return "\"" + raw.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "\"";
    }
}
