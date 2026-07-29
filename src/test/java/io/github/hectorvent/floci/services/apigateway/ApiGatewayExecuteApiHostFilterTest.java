package io.github.hectorvent.floci.services.apigateway;

import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.services.apigatewayv2.ApiGatewayV2Service;
import io.github.hectorvent.floci.services.apigatewayv2.model.Api;
import io.github.hectorvent.floci.services.apigatewayv2.model.Stage;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

class ApiGatewayExecuteApiHostFilterTest {

    private static final String API_ID = "abc123";
    private static final String REGION = "us-east-1";

    @Test
    void routesStageLessRequestToDefaultStageAndPreservesQuery() {
        ApiGatewayV2Service service = mock(ApiGatewayV2Service.class);
        when(service.getApi(REGION, API_ID)).thenReturn(api());
        when(service.getStage(REGION, API_ID, "accounts"))
                .thenThrow(new AwsException("NotFoundException", "Stage not found", 404));
        when(service.getStage(REGION, API_ID, "$default")).thenReturn(stage("$default"));

        ContainerRequestContext context = context(
                "abc123.execute-api.localhost.floci.io:4566",
                URI.create("http://abc123.execute-api.localhost.floci.io:4566/accounts?tenant=alpha"));

        new ApiGatewayExecuteApiHostFilter(service, new RegionResolver(REGION, "000000000000"))
                .filter(context);

        ArgumentCaptor<URI> uri = ArgumentCaptor.forClass(URI.class);
        verify(context).setRequestUri(uri.capture());
        assertEquals("/execute-api/abc123/$default/accounts", uri.getValue().getPath());
        assertEquals("tenant=alpha", uri.getValue().getQuery());
    }

    @Test
    void routesExplicitStageAndRemovesItFromRemainingPath() {
        ApiGatewayV2Service service = mock(ApiGatewayV2Service.class);
        when(service.getApi(REGION, API_ID)).thenReturn(api());
        when(service.getStage(REGION, API_ID, "dev")).thenReturn(stage("dev"));

        ContainerRequestContext context = context(
                "abc123.execute-api.localhost.localstack.cloud",
                URI.create("http://abc123.execute-api.localhost.localstack.cloud/dev/accounts"));

        new ApiGatewayExecuteApiHostFilter(service, new RegionResolver(REGION, "000000000000"))
                .filter(context);

        ArgumentCaptor<URI> uri = ArgumentCaptor.forClass(URI.class);
        verify(context).setRequestUri(uri.capture());
        assertEquals("/execute-api/abc123/dev/accounts", uri.getValue().getPath());
    }

    @Test
    void ignoresNonExecuteApiHost() {
        ApiGatewayV2Service service = mock(ApiGatewayV2Service.class);
        ContainerRequestContext context = context(
                "localhost:4566",
                URI.create("http://localhost:4566/accounts"));

        new ApiGatewayExecuteApiHostFilter(service, new RegionResolver(REGION, "000000000000"))
                .filter(context);

        verify(context, never()).setRequestUri(any(URI.class));
        verifyNoInteractions(service);
    }

    private static ContainerRequestContext context(String host, URI requestUri) {
        ContainerRequestContext context = mock(ContainerRequestContext.class);
        UriInfo uriInfo = mock(UriInfo.class);
        when(context.getHeaderString("Host")).thenReturn(host);
        when(context.getHeaderString("Authorization")).thenReturn(null);
        when(context.getUriInfo()).thenReturn(uriInfo);
        when(uriInfo.getRequestUri()).thenReturn(requestUri);
        return context;
    }

    private static Api api() {
        Api api = new Api();
        api.setApiId(API_ID);
        api.setProtocolType("HTTP");
        return api;
    }

    private static Stage stage(String name) {
        Stage stage = new Stage();
        stage.setStageName(name);
        return stage;
    }
}
