package io.github.hectorvent.floci.services.apigateway;

import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.services.apigatewayv2.ApiGatewayV2Service;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.PreMatching;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;

import java.net.URI;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Routes API Gateway v2 requests advertised through Floci's local execute-api
 * hostname to the path-based data-plane controller.
 */
@Provider
@PreMatching
@Priority(9)
public class ApiGatewayExecuteApiHostFilter implements ContainerRequestFilter {

    private static final Logger LOG = Logger.getLogger(ApiGatewayExecuteApiHostFilter.class);
    private static final Pattern EXECUTE_API_HOST = Pattern.compile(
            "^([a-z0-9-]+)\\.execute-api\\.localhost\\.(?:floci\\.io|localstack\\.cloud)$",
            Pattern.CASE_INSENSITIVE);

    private final ApiGatewayV2Service apiGatewayV2Service;
    private final RegionResolver regionResolver;

    @Inject
    public ApiGatewayExecuteApiHostFilter(ApiGatewayV2Service apiGatewayV2Service,
                                          RegionResolver regionResolver) {
        this.apiGatewayV2Service = apiGatewayV2Service;
        this.regionResolver = regionResolver;
    }

    @Override
    public void filter(ContainerRequestContext requestContext) {
        String host = requestContext.getHeaderString("Host");
        if (host == null) {
            return;
        }

        Matcher matcher = EXECUTE_API_HOST.matcher(stripPort(host));
        if (!matcher.matches()) {
            return;
        }

        String apiId = matcher.group(1);
        String region = regionResolver.resolveRegionFromAuth(
                requestContext.getHeaderString("Authorization"));
        try {
            apiGatewayV2Service.getApi(region, apiId);
        } catch (AwsException ignored) {
            return;
        }

        URI originalUri = requestContext.getUriInfo().getRequestUri();
        String originalPath = originalUri.getRawPath();
        String path = originalPath == null ? "" : stripLeadingSlash(originalPath);
        String firstSegment = firstSegment(path);

        String stageName = "$default";
        String remainingPath = path;
        if (!firstSegment.isEmpty() && stageExists(region, apiId, firstSegment)) {
            stageName = firstSegment;
            remainingPath = stripFirstSegment(path);
        } else if (!stageExists(region, apiId, stageName)) {
            return;
        }

        String newPath = "/execute-api/" + apiId + "/" + stageName;
        if (!remainingPath.isEmpty()) {
            newPath += "/" + remainingPath;
        }

        URI newUri = UriBuilder.fromUri(originalUri)
                .replacePath(newPath)
                .build();
        LOG.debugv("Execute API host routing: {0}{1} -> {2}", host, originalPath, newUri.getPath());
        requestContext.setRequestUri(newUri);
    }

    private boolean stageExists(String region, String apiId, String stageName) {
        try {
            apiGatewayV2Service.getStage(region, apiId, stageName);
            return true;
        } catch (AwsException ignored) {
            return false;
        }
    }

    private static String stripPort(String host) {
        int colonIndex = host.lastIndexOf(':');
        if (colonIndex > 0) {
            String port = host.substring(colonIndex + 1);
            if (!port.isEmpty() && port.chars().allMatch(Character::isDigit)) {
                return host.substring(0, colonIndex);
            }
        }
        return host;
    }

    private static String stripLeadingSlash(String path) {
        return path.startsWith("/") ? path.substring(1) : path;
    }

    private static String firstSegment(String path) {
        int slash = path.indexOf('/');
        return slash >= 0 ? path.substring(0, slash) : path;
    }

    private static String stripFirstSegment(String path) {
        int slash = path.indexOf('/');
        return slash >= 0 ? path.substring(slash + 1) : "";
    }
}
