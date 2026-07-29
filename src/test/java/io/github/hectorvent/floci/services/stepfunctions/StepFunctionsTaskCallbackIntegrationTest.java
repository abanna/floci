package io.github.hectorvent.floci.services.stepfunctions;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@QuarkusTest
class StepFunctionsTaskCallbackIntegrationTest {

    private static final String SFN_CONTENT_TYPE = "application/x-amz-json-1.0";
    private static final String ROLE_ARN = "arn:aws:iam::000000000000:role/test-role";
    private static final ObjectMapper mapper = new ObjectMapper();

    @Inject
    StepFunctionsService stepFunctionsService;

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void sfnSendTaskFailureCompletesPendingCallbackAndReturnsEmptySdkResult() throws Exception {
        String taskToken = "sdk-send-failure-" + System.nanoTime();
        var pending = stepFunctionsService.registerPendingToken(taskToken);

        String output = execute("sfn-send-failure",
                "arn:aws:states:::aws-sdk:sfn:sendTaskFailure", """
                        {
                          "TaskToken": "%s",
                          "Error": "ProvisioningFailed",
                          "Cause": "executor exited"
                        }
                        """.formatted(taskToken));

        assertTrue(mapper.readTree(output).isObject());
        ExecutionException failure = assertThrows(
                ExecutionException.class, () -> pending.get(1, TimeUnit.SECONDS));
        AslExecutor.FailStateException callbackFailure =
                assertInstanceOf(AslExecutor.FailStateException.class, failure.getCause());
        assertEquals("ProvisioningFailed", callbackFailure.error);
        assertEquals("executor exited", callbackFailure.cause);
    }

    @Test
    void sfnSendTaskSuccessCompletesPendingCallbackAndReturnsEmptySdkResult() throws Exception {
        String taskToken = "sdk-send-success-" + System.nanoTime();
        var pending = stepFunctionsService.registerPendingToken(taskToken);

        String output = execute("sfn-send-success",
                "arn:aws:states:::aws-sdk:sfn:sendTaskSuccess", """
                        {
                          "TaskToken": "%s",
                          "Output": "{\\"provisioned\\":true}"
                        }
                        """.formatted(taskToken));

        assertTrue(mapper.readTree(output).isObject());
        assertTrue(pending.get(1, TimeUnit.SECONDS).path("provisioned").asBoolean());
    }

    @Test
    void sfnSendTaskHeartbeatIsSupported() throws Exception {
        String taskToken = "sdk-heartbeat-" + System.nanoTime();
        var pending = stepFunctionsService.registerPendingToken(taskToken);
        String output = execute("sfn-send-heartbeat",
                "arn:aws:states:::aws-sdk:sfn:sendTaskHeartbeat", """
                        {"TaskToken": "%s"}
                        """.formatted(taskToken));
        assertTrue(mapper.readTree(output).isObject());
        assertFalse(pending.isDone());

        stepFunctionsService.sendTaskSuccess(taskToken, "{}");
        assertTrue(pending.get(1, TimeUnit.SECONDS).isObject());
    }

    @Test
    void taskCallbacksRejectInvalidOutputUnknownAndTerminalTokens() throws Exception {
        String taskToken = "callback-validation-" + System.nanoTime();
        var pending = stepFunctionsService.registerPendingToken(taskToken);

        AwsException unknownInvalidOutput = assertThrows(AwsException.class,
                () -> stepFunctionsService.sendTaskSuccess(
                        "unknown-" + System.nanoTime(), "{"));
        assertEquals("InvalidToken", unknownInvalidOutput.getErrorCode());

        AwsException invalidOutput = assertThrows(AwsException.class,
                () -> stepFunctionsService.sendTaskSuccess(taskToken, "{"));
        assertEquals("InvalidOutput", invalidOutput.getErrorCode());
        assertFalse(pending.isDone(), "invalid output must not consume the task token");

        stepFunctionsService.sendTaskSuccess(taskToken, "{\"accepted\":true}");
        assertTrue(pending.get(1, TimeUnit.SECONDS).path("accepted").asBoolean());

        AwsException terminal = assertThrows(AwsException.class,
                () -> stepFunctionsService.sendTaskHeartbeat(taskToken));
        assertEquals("TaskTimedOut", terminal.getErrorCode());

        AwsException terminalInvalidOutput = assertThrows(AwsException.class,
                () -> stepFunctionsService.sendTaskSuccess(taskToken, "{"));
        assertEquals("TaskTimedOut", terminalInvalidOutput.getErrorCode());

        AwsException unknown = assertThrows(AwsException.class,
                () -> stepFunctionsService.sendTaskFailure(
                        "unknown-" + System.nanoTime(), "cause", "error"));
        assertEquals("InvalidToken", unknown.getErrorCode());
    }

    @Test
    void lateCallbackAfterTimeoutReturnsTaskTimedOut() {
        String taskToken = "callback-timeout-" + System.nanoTime();
        var pending = stepFunctionsService.registerPendingToken(taskToken);

        stepFunctionsService.timeoutPendingToken(taskToken, pending);

        assertTrue(pending.isCancelled());
        AwsException error = assertThrows(AwsException.class,
                () -> stepFunctionsService.sendTaskSuccess(taskToken, "{}"));
        assertEquals("TaskTimedOut", error.getErrorCode());
    }

    @Test
    void startSyncExecutionRunsExpressStateMachineToCompletion() throws Exception {
        String definition = """
                {"StartAt":"Done","States":{
                  "Done":{"Type":"Pass","Result":{"sync":true},"End":true}}}
                """;
        Response create = given()
                .header("X-Amz-Target", "AWSStepFunctions.CreateStateMachine")
                .contentType(SFN_CONTENT_TYPE)
                .body("""
                        {"name":"sync-express-%d","definition":%s,"roleArn":"%s","type":"EXPRESS"}
                        """.formatted(System.nanoTime(), quote(definition), ROLE_ARN))
            .when()
                .post("/");
        create.then().statusCode(200);

        given()
                .header("X-Amz-Target", "AWSStepFunctions.StartSyncExecution")
                .contentType(SFN_CONTENT_TYPE)
                .body("""
                        {"stateMachineArn":"%s","input":"{}"}
                        """.formatted(create.jsonPath().getString("stateMachineArn")))
            .when()
                .post("/")
            .then()
                .statusCode(200)
                .body("status", org.hamcrest.Matchers.equalTo("SUCCEEDED"))
                .body("output", org.hamcrest.Matchers.equalTo("{\"sync\":true}"));
    }

    private String execute(String nameSuffix, String resource, String parameters) throws Exception {
        String definition = """
                {"StartAt":"Action","States":{"Action":{"Type":"Task","Resource":"%s","Parameters":%s,"End":true}}}
                """.formatted(resource, parameters.strip());
        String smArn = createStateMachine(nameSuffix + "-" + System.currentTimeMillis(), definition);
        String execArn = startExecution(smArn);
        return waitForExecution(execArn);
    }

    private String createStateMachine(String name, String definition) {
        Response response = given()
                .header("X-Amz-Target", "AWSStepFunctions.CreateStateMachine")
                .contentType(SFN_CONTENT_TYPE)
                .body("""
                        {"name": "%s", "definition": %s, "roleArn": "%s"}
                        """.formatted(name, quote(definition), ROLE_ARN))
                .when().post("/");
        response.then().statusCode(200);
        return response.jsonPath().getString("stateMachineArn");
    }

    private String startExecution(String stateMachineArn) {
        Response response = given()
                .header("X-Amz-Target", "AWSStepFunctions.StartExecution")
                .contentType(SFN_CONTENT_TYPE)
                .body("""
                        {"stateMachineArn": "%s", "input": "{}"}
                        """.formatted(stateMachineArn))
                .when().post("/");
        response.then().statusCode(200);
        return response.jsonPath().getString("executionArn");
    }

    private String waitForExecution(String executionArn) throws InterruptedException {
        for (int i = 0; i < 50; i++) {
            Response response = given()
                    .header("X-Amz-Target", "AWSStepFunctions.DescribeExecution")
                    .contentType(SFN_CONTENT_TYPE)
                    .body("""
                            {"executionArn": "%s"}
                            """.formatted(executionArn))
                    .when().post("/");
            String status = response.jsonPath().getString("status");
            if ("SUCCEEDED".equals(status)) {
                return response.jsonPath().getString("output");
            }
            if ("FAILED".equals(status) || "ABORTED".equals(status) || "TIMED_OUT".equals(status)) {
                fail("Execution " + status + ": " + response.body().asString());
            }
            Thread.sleep(100);
        }
        fail("Execution did not complete within timeout");
        return null;
    }

    private static String quote(String raw) {
        return "\"" + raw
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t")
                + "\"";
    }
}
