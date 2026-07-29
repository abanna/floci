package io.github.hectorvent.floci.services.cloudformation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.services.cloudformation.model.StackResource;
import io.github.hectorvent.floci.services.cloudformation.provisioners.CloudFormationResourceRegistry;
import io.github.hectorvent.floci.services.secretsmanager.SecretsManagerService;
import io.github.hectorvent.floci.services.secretsmanager.model.Secret;
import io.github.hectorvent.floci.services.secretsmanager.model.SecretVersion;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CloudFormationSecretProvisionerTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT_ID = "000000000000";
    private static final String SECRET_NAME = "legacy-generated-secret";
    private static final String SECRET_ARN =
            "arn:aws:secretsmanager:us-east-1:000000000000:secret:legacy-generated-secret-a1b2c3";

    private final ObjectMapper mapper = new ObjectMapper();
    private SecretsManagerService secretsManagerService;
    private CloudFormationResourceProvisioner provisioner;

    @BeforeEach
    void setUp() {
        secretsManagerService = mock(SecretsManagerService.class);
        provisioner = new CloudFormationResourceProvisioner(
                null, null, null, null, null, null, null, null, secretsManagerService, null,
                null, null, null, null, null, null,
                mapper,
                null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null,
                new CloudFormationResourceRegistry(List.of()));

        Secret secret = new Secret();
        secret.setName(SECRET_NAME);
        secret.setArn(SECRET_ARN);
        when(secretsManagerService.describeSecret(SECRET_ARN, REGION)).thenReturn(secret);
        SecretVersion current = new SecretVersion();
        current.setSecretString("legacy-value");
        when(secretsManagerService.getSecretValue(SECRET_ARN, null, null, REGION))
                .thenReturn(current);
    }

    @Test
    void legacyGeneratedSecretRotatesOnceToEstablishValueSpecFingerprint() throws Exception {
        JsonNode properties = mapper.readTree("""
                {
                  "Name": "legacy-generated-secret",
                  "GenerateSecretString": {
                    "PasswordLength": 24,
                    "ExcludePunctuation": true
                  }
                }
                """);

        StackResource migrated = provision(properties, Map.of());

        assertEquals("CREATE_COMPLETE", migrated.getStatus());
        ArgumentCaptor<String> generatedValue = ArgumentCaptor.forClass(String.class);
        verify(secretsManagerService).putSecretValue(
                eq(SECRET_ARN), generatedValue.capture(), isNull(), isNull(),
                eq(REGION), isNull());
        assertEquals(24, generatedValue.getValue().length());
        assertFalse(generatedValue.getValue().equals("legacy-value"));

        StackResource unchanged = provision(properties, migrated.getAttributes());

        assertEquals("CREATE_COMPLETE", unchanged.getStatus());
        verify(secretsManagerService, times(1)).putSecretValue(
                eq(SECRET_ARN), org.mockito.ArgumentMatchers.anyString(),
                isNull(), isNull(), eq(REGION), isNull());
    }

    private StackResource provision(JsonNode properties, Map<String, String> attributes) {
        return provisioner.provision(
                "Secret", "AWS::SecretsManager::Secret", properties, engine(),
                REGION, ACCOUNT_ID, "stack", SECRET_ARN, attributes);
    }

    private CloudFormationTemplateEngine engine() {
        return new CloudFormationTemplateEngine(
                ACCOUNT_ID, REGION, "stack", "stack/id",
                Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), mapper,
                (Function<String, String>) name -> null);
    }
}
