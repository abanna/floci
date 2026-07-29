package io.github.hectorvent.floci.services.cloudfront;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.services.cloudfront.model.Distribution;
import io.github.hectorvent.floci.services.cloudfront.model.DistributionConfig;
import io.github.hectorvent.floci.services.cloudfront.model.Origin;
import io.github.hectorvent.floci.services.s3.S3Controller;
import io.github.hectorvent.floci.services.s3.S3Service;
import io.github.hectorvent.floci.services.s3.model.S3Object;
import io.quarkus.vertx.http.runtime.CurrentVertxRequest;
import jakarta.annotation.PreDestroy;
import jakarta.inject.Inject;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HEAD;
import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jboss.logging.Logger;

import javax.net.ssl.SSLContext;
import java.net.IDN;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Serves viewer requests routed to a CloudFront distribution (via {@link CloudFrontDistributionFilter})
 * by resolving the matching cache behavior + origin and returning the origin content, implemented to
 * the AWS CloudFront data-plane spec.
 *
 * <p>The internal path is {@code /_cloudfront/{distId}/{proxy:.*}}; {@code proxy} is the viewer's path
 * relative to the distribution. Routing (behavior/path-pattern matching, default-root-object, origin
 * path) is delegated to {@link CloudFrontRequestRouter}. This controller performs the origin I/O:
 *
 * <ul>
 *   <li>S3 origins are served in-process through {@link S3Service} (the bucket is derived from the
 *       origin domain name).</li>
 *   <li>Custom origins are fetched over HTTP(S) with {@link java.net.http.HttpClient}.</li>
 *   <li>When an origin returns an error status, a matching {@code CustomErrorResponse} is applied —
 *       most importantly the single-page-app fallback that rewrites 403/404 to 200 {@code /index.html}.
 *       If the configured error page is itself missing, the received status is returned (no loop).</li>
 * </ul>
 *
 * <p>Viewer-protocol-policy enforcement is intentionally out of scope for this layer: the emulator
 * is HTTP-first. Viewer methods are checked against the matched cache behavior before origin I/O.
 */
@Path("/_cloudfront/{distId}")
public class CloudFrontServingController {

    private static final Logger LOG = Logger.getLogger(CloudFrontServingController.class);
    private static final String DEFAULT_CONTENT_TYPE = "application/octet-stream";
    private static final DateTimeFormatter HTTP_DATE = DateTimeFormatter.RFC_1123_DATE_TIME
            .withZone(ZoneOffset.UTC);
    private static final Set<String> FORBIDDEN_POLICY_RESPONSE_HEADERS = Set.of(
            "connection", "content-length", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "proxy-connection", "te", "trailer",
            "transfer-encoding", "upgrade", "via");
    private static final Set<String> NON_FORWARDED_RESPONSE_HEADERS = Set.of(
            "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
            "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade", "via",
            "content-length", "content-type");

    private static final java.util.Set<String> CLOUDFRONT_SIGNING_PARAMS =
            java.util.Set.of("Expires", "Signature", "Key-Pair-Id", "Policy", "Hash-Algorithm");

    private final CloudFrontService service;
    private final S3Service s3Service;
    private final S3Controller s3Controller;
    private final CurrentVertxRequest currentVertxRequest;
    private final CloudFrontOriginHttpClient httpClient;

    @Inject
    public CloudFrontServingController(CloudFrontService service, S3Service s3Service,
                                       S3Controller s3Controller,
                                       EmulatorConfig emulatorConfig,
                                       CurrentVertxRequest currentVertxRequest) {
        this.service = service;
        this.s3Service = s3Service;
        this.s3Controller = s3Controller;
        this.currentVertxRequest = currentVertxRequest;
        SSLContext originSslContext = null;
        if (emulatorConfig.tls().enabled()) {
            java.nio.file.Path certificatePath = emulatorConfig.tls().certPath()
                    .or(() -> ConfigProvider.getConfig().getOptionalValue(
                            "quarkus.http.ssl.certificate.files", String.class))
                    .map(java.nio.file.Path::of)
                    .orElseGet(() -> java.nio.file.Path.of(
                            emulatorConfig.storage().persistentPath(),
                            "tls", "floci-selfsigned.crt"));
            try {
                originSslContext =
                        CloudFrontOriginHttpClient.sslContextWithAdditionalTrustCertificate(
                                certificatePath);
            } catch (Exception e) {
                LOG.warnv("Could not add the local Floci TLS certificate to custom-origin trust: {0}",
                        e.getClass().getSimpleName());
            }
        }
        this.httpClient = new CloudFrontOriginHttpClient(
                emulatorConfig.services().cloudfront().allowedPrivateOriginHosts().orElse(List.of()),
                originSslContext);
    }

    @PreDestroy
    void closeHttpClient() {
        try {
            httpClient.close();
        } catch (Exception e) {
            LOG.debugv("Could not close CloudFront origin HTTP client: {0}", e.getMessage());
        }
    }

    @GET
    @Path("/{proxy:.*}")
    public Response get(@PathParam("distId") String distId, @PathParam("proxy") String proxy,
                        @Context HttpHeaders headers, @Context UriInfo uriInfo) {
        var request = currentVertxRequest.getCurrent().request();
        String rawViewerPath = rawViewerPath(currentVertxRequest.getCurrent().request().uri());
        return serve(distId, rawViewerPath, decodedViewerPath(rawViewerPath),
                request.query(), uriInfo.getRequestUri().getScheme(), headers.getHeaderString("Host"),
                request.getHeader("Origin"), "GET", null, null, null,
                headers, uriInfo);
    }

    @HEAD
    @Path("/{proxy:.*}")
    public Response head(@PathParam("distId") String distId, @PathParam("proxy") String proxy,
                         @Context HttpHeaders headers, @Context UriInfo uriInfo) {
        var request = currentVertxRequest.getCurrent().request();
        String rawViewerPath = rawViewerPath(request.uri());
        return serve(distId, rawViewerPath, decodedViewerPath(rawViewerPath),
                request.query(), uriInfo.getRequestUri().getScheme(), headers.getHeaderString("Host"),
                request.getHeader("Origin"), "HEAD", null, null, null,
                headers, uriInfo);
    }

    @POST
    @Path("/{proxy:.*}")
    public Response post(@PathParam("distId") String distId, @PathParam("proxy") String proxy,
                         byte[] body, @Context HttpHeaders headers, @Context UriInfo uriInfo) {
        return serveWithBody(distId, headers, uriInfo, "POST", body);
    }

    @PUT
    @Path("/{proxy:.*}")
    public Response put(@PathParam("distId") String distId, @PathParam("proxy") String proxy,
                        byte[] body, @Context HttpHeaders headers, @Context UriInfo uriInfo) {
        return serveWithBody(distId, headers, uriInfo, "PUT", body);
    }

    @PATCH
    @Path("/{proxy:.*}")
    public Response patch(@PathParam("distId") String distId, @PathParam("proxy") String proxy,
                          byte[] body, @Context HttpHeaders headers, @Context UriInfo uriInfo) {
        return serveWithBody(distId, headers, uriInfo, "PATCH", body);
    }

    @DELETE
    @Path("/{proxy:.*}")
    public Response delete(@PathParam("distId") String distId, @PathParam("proxy") String proxy,
                           byte[] body, @Context HttpHeaders headers, @Context UriInfo uriInfo) {
        return serveWithBody(distId, headers, uriInfo, "DELETE", body);
    }

    private Response serveWithBody(String distId, HttpHeaders headers, UriInfo uriInfo,
                                   String method, byte[] body) {
        var request = currentVertxRequest.getCurrent().request();
        String rawViewerPath = rawViewerPath(request.uri());
        return serve(distId, rawViewerPath, decodedViewerPath(rawViewerPath),
                request.query(), uriInfo.getRequestUri().getScheme(), headers.getHeaderString("Host"),
                request.getHeader("Origin"), method, null, null,
                body != null ? body : new byte[0], headers, uriInfo);
    }

    @OPTIONS
    @Path("/{proxy:.*}")
    public Response options(@PathParam("distId") String distId, @PathParam("proxy") String proxy,
                            @Context HttpHeaders headers, @Context UriInfo uriInfo) {
        var request = currentVertxRequest.getCurrent().request();
        String rawViewerPath = rawViewerPath(request.uri());
        return serve(distId, rawViewerPath, decodedViewerPath(rawViewerPath),
                request.query(), uriInfo.getRequestUri().getScheme(), headers.getHeaderString("Host"),
                request.getHeader("Origin"), "OPTIONS",
                request.getHeader("Access-Control-Request-Method"),
                request.getHeader("Access-Control-Request-Headers"), null,
                headers, uriInfo);
    }

    private Response serve(String distId, String rawViewerPath, String decodedViewerPath,
                           String rawQuery, String viewerScheme, String viewerHost,
                           String viewerOrigin, String method,
                           String accessControlRequestMethod,
                           String accessControlRequestHeaders, byte[] requestBody,
                           HttpHeaders requestHeaders, UriInfo uriInfo) {
        boolean includeBody = !"HEAD".equals(method);
        boolean preflightRequest = "OPTIONS".equals(method)
                && viewerOrigin != null && !viewerOrigin.isBlank()
                && accessControlRequestMethod != null && !accessControlRequestMethod.isBlank();
        Distribution dist = service.findByHost(viewerHost);
        if (dist == null || !distId.equals(dist.getId())) {
            return textError(404, "Distribution not found.");
        }
        DistributionConfig config = dist.getConfig();
        if (config == null) {
            return textError(502, "Distribution has no configuration.");
        }
        if (!config.isEnabled()) {
            return textError(404, "Distribution is disabled.");
        }
        String normalized = CloudFrontRequestRouter.normalizePath(decodedViewerPath);
        if (!CloudFrontRequestRouter.isMethodAllowed(config, normalized, method)) {
            return textError(403, "Method not allowed.");
        }

        // The response-headers policy of the behavior that matches the request applies to the final
        // response CloudFront returns to the viewer, including any custom-error page substituted below.
        ResponseHeadersPolicyConfigCodec.Directives directives = responseHeaderDirectives(
                CloudFrontRequestRouter.matchResponseHeadersPolicyId(config, normalized),
                viewerOrigin, preflightRequest);

        // Private content: when the matched cache behavior trusts key groups, the request must carry a
        // valid CloudFront signature (signed URL or signed cookies), otherwise CloudFront returns 403.
        String originQuery = rawQuery;
        List<String> trustedKeyGroups = CloudFrontRequestRouter.trustedKeyGroupsFor(config, normalized);
        if (!trustedKeyGroups.isEmpty()) {
            CloudFrontSignatureVerifier.Result verdict = verifySignedRequest(dist, trustedKeyGroups, uriInfo);
            if (!verdict.allowed()) {
                LOG.debugv("CloudFront denied a request for {0}{1}: {2}",
                        dist.getId(), rawViewerPath, verdict.reason());
                return textError(403, "Access denied: " + verdict.reason());
            }
            // CloudFront consumes signed-URL fields and does not forward them to the origin.
            originQuery = stripCloudFrontSigningParams(rawQuery);
        }

        OriginResponse origin = route(config, normalized, rawViewerPath, decodedViewerPath,
                originQuery, viewerScheme, method, viewerOrigin,
                accessControlRequestMethod, accessControlRequestHeaders,
                requestBody, requestHeaders, uriInfo);

        if (origin.status() >= 400) {
            Response fallback = applyCustomError(
                    config, origin, viewerScheme, includeBody, directives);
            if (fallback != null) {
                return fallback;
            }
        }
        return toResponse(origin, includeBody, directives);
    }

    /** Resolves the response-headers policy for a behavior into the headers it contributes, if any. */
    private ResponseHeadersPolicyConfigCodec.Directives responseHeaderDirectives(
            String policyId, String viewerOrigin, boolean preflightRequest) {
        if (policyId == null || policyId.isBlank()) {
            return null;
        }
        try {
            return ResponseHeadersPolicyConfigCodec.directives(
                    service.getResponseHeadersPolicy(policyId).getConfig(), viewerOrigin,
                    preflightRequest);
        } catch (AwsException e) {
            LOG.warnv("Distribution references missing response headers policy {0}", policyId);
            return null;
        }
    }

    /**
     * Verifies the live request against the behavior's trusted key groups, resolving a Key-Pair-Id to
     * its public key only when that key is a member of one of those groups.
     */
    private CloudFrontSignatureVerifier.Result verifySignedRequest(Distribution dist,
                                                                   List<String> trustedKeyGroups, UriInfo uriInfo) {
        io.vertx.core.http.HttpServerRequest request = currentVertxRequest.getCurrent().request();

        Map<String, String> query = new java.util.LinkedHashMap<>();
        for (String name : request.params().names()) {
            query.put(name, request.getParam(name));
        }
        Map<String, String> cookies = parseCookies(request.getHeader("Cookie"));
        String resourceUrl = buildResourceUrl(dist, request, uriInfo);
        String sourceIp = request.remoteAddress() != null ? request.remoteAddress().hostAddress() : null;

        return CloudFrontSignatureVerifier.verify(resourceUrl, query, cookies, sourceIp,
                keyPairId -> service.trustedPublicKeyPem(keyPairId, trustedKeyGroups), java.time.Instant.now());
    }

    /**
     * Rebuilds the URL a signer would have signed: {@code scheme://host<path>[?app-query]}. The path
     * and query are taken RAW from the Vert.x request — a signer signs the percent-encoded URL, so
     * using the JAX-RS-decoded path/params here would make a legitimately signed request for an
     * encoded path (e.g. {@code /a%20b.jpg}) fail to match its own signature.
     */
    private static String buildResourceUrl(Distribution dist, io.vertx.core.http.HttpServerRequest request,
                                           UriInfo uriInfo) {
        String scheme = request.scheme() != null ? request.scheme() : "https";
        String host = request.getHeader("Host");
        if (host == null || host.isBlank()) {
            host = dist.getDomainName();
        }
        // A signer signs the percent-encoded URL, so the resource must be rebuilt from the RAW path and
        // query (Vert.x request.path()/getParam() are already decoded). The PreMatching filter routed the
        // request to /_cloudfront/{distId}{rawPath} preserving the encoding, so recover the viewer path
        // by stripping that prefix from UriInfo's raw path.
        String rawPath = uriInfo.getRequestUri().getRawPath();
        String prefix = "/_cloudfront/" + dist.getId();
        if (rawPath.startsWith(prefix)) {
            rawPath = rawPath.substring(prefix.length());
        }
        if (rawPath.isEmpty()) {
            rawPath = "/";
        }
        return scheme + "://" + host + rawPath + rawAppQuery(uriInfo.getRequestUri().getRawQuery());
    }

    /** The raw (encoding-preserved) query string minus the CloudFront signing params. */
    private static String rawAppQuery(String rawQuery) {
        String appQuery = stripCloudFrontSigningParams(rawQuery);
        return appQuery.isEmpty() ? "" : "?" + appQuery;
    }

    static String stripCloudFrontSigningParams(String rawQuery) {
        if (rawQuery == null || rawQuery.isEmpty()) {
            return "";
        }
        StringBuilder appQuery = new StringBuilder();
        for (String pair : rawQuery.split("&", -1)) {
            int eq = pair.indexOf('=');
            String rawName = eq >= 0 ? pair.substring(0, eq) : pair;
            String decodedName = decodeQueryName(rawName);
            if (decodedName != null && CLOUDFRONT_SIGNING_PARAMS.contains(decodedName)) {
                continue;
            }
            if (appQuery.length() > 0) {
                appQuery.append('&');
            }
            appQuery.append(pair);
        }
        return appQuery.toString();
    }

    private static String decodeQueryName(String rawName) {
        try {
            return java.net.URLDecoder.decode(rawName, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            LOG.debugv("Preserving malformed CloudFront query parameter name {0}: {1}",
                    rawName, e.getMessage());
            return null;
        }
    }

    private static Map<String, String> parseCookies(String cookieHeader) {
        Map<String, String> cookies = new java.util.LinkedHashMap<>();
        if (cookieHeader == null || cookieHeader.isBlank()) {
            return cookies;
        }
        for (String part : cookieHeader.split(";")) {
            int eq = part.indexOf('=');
            if (eq > 0) {
                cookies.put(part.substring(0, eq).trim(), part.substring(eq + 1).trim());
            }
        }
        return cookies;
    }

    /** Selects an origin with the normalized path, then forwards the original viewer path. */
    private OriginResponse route(DistributionConfig config, String normalized,
                                 String rawViewerPath, String decodedViewerPath,
                                 String rawQuery, String viewerScheme, String method,
                                 String viewerOrigin, String accessControlRequestMethod,
                                 String accessControlRequestHeaders, byte[] requestBody,
                                 HttpHeaders requestHeaders, UriInfo uriInfo) {
        String originId = CloudFrontRequestRouter.matchTargetOriginId(config, normalized);
        Origin origin = CloudFrontRequestRouter.findOrigin(config, originId);
        if (origin == null) {
            return OriginResponse.error(502, "No origin matched the request.");
        }
        if (CloudFrontRequestRouter.isS3Origin(origin)) {
            if ("OPTIONS".equals(method)) {
                return fetchS3Preflight(origin, viewerOrigin, accessControlRequestMethod,
                        accessControlRequestHeaders);
            }
            String key = CloudFrontRequestRouter.resolveOriginKey(
                    origin.getOriginPath(), decodedViewerPath, config.getDefaultRootObject());
            return switch (method) {
                case "GET" -> fetchFromS3(origin, key, true);
                case "HEAD" -> fetchFromS3(origin, key, false);
                case "PUT" -> putToS3(origin, key, requestBody, viewerHeaders(requestHeaders));
                case "DELETE" -> deleteFromS3(origin, key);
                case "POST" -> postToS3(origin, key, rawQuery, requestBody,
                        requestHeaders, uriInfo);
                case "PATCH" -> patchToS3(origin, key);
                default -> OriginResponse.error(405, "Method not allowed.");
            };
        }
        String forwardUri = CloudFrontRequestRouter.resolveForwardUri(
                origin.getOriginPath(), rawViewerPath, config.getDefaultRootObject());
        return fetchFromCustomOrigin(
                origin, forwardUri, rawQuery, viewerScheme, method, viewerOrigin,
                accessControlRequestMethod, accessControlRequestHeaders,
                requestBody, viewerHeaders(requestHeaders));
    }

    private OriginResponse fetchFromS3(Origin origin, String key, boolean includeBody) {
        String bucket = CloudFrontRequestRouter.bucketFromS3Domain(origin.getDomainName());
        if (bucket == null) {
            return OriginResponse.error(502, "Could not determine S3 bucket for origin.");
        }
        try {
            s3Service.authorizeAnonymousGetObject(bucket, key);
            if (includeBody) {
                S3Object obj = s3Service.getObject(bucket, key);
                byte[] data = obj.getData() != null ? obj.getData() : new byte[0];
                return new OriginResponse(
                        200, contentType(obj), data, data.length, s3ObjectHeaders(obj));
            }
            S3Object meta = s3Service.headObject(bucket, key);
            return new OriginResponse(
                    200, contentType(meta), null, meta.getSize(), s3ObjectHeaders(meta));
        } catch (AwsException e) {
            return OriginResponse.error(e.getHttpStatus(), e.getMessage());
        }
    }

    private OriginResponse putToS3(
            Origin origin, String key, byte[] requestBody,
            Map<String, String> viewerHeaders) {
        String bucket = CloudFrontRequestRouter.bucketFromS3Domain(origin.getDomainName());
        if (bucket == null) {
            return OriginResponse.error(502, "Could not determine S3 bucket for origin.");
        }
        try {
            s3Service.authorizeAnonymousPutObject(bucket, key);
            String contentType = viewerHeaders != null
                    ? viewerHeaders.get("Content-Type")
                    : null;
            S3Object object = s3Service.putObject(
                    bucket, key,
                    requestBody != null ? requestBody : new byte[0],
                    contentType, Map.of());
            Map<String, List<String>> headers = new LinkedHashMap<>();
            putHeader(headers, "ETag", object.getETag());
            if (object.getVersionId() != null) {
                putHeader(headers, "x-amz-version-id", object.getVersionId());
            }
            return new OriginResponse(200, null, new byte[0], 0, headers);
        } catch (AwsException e) {
            return OriginResponse.error(e.getHttpStatus(), e.getMessage());
        }
    }

    private OriginResponse deleteFromS3(Origin origin, String key) {
        String bucket = CloudFrontRequestRouter.bucketFromS3Domain(origin.getDomainName());
        if (bucket == null) {
            return OriginResponse.error(502, "Could not determine S3 bucket for origin.");
        }
        try {
            s3Service.authorizeAnonymousDeleteObject(bucket, key);
            S3Object object = s3Service.deleteObject(bucket, key);
            Map<String, List<String>> headers = new LinkedHashMap<>();
            if (object != null) {
                if (object.isDeleteMarker()) {
                    putHeader(headers, "x-amz-delete-marker", "true");
                }
                putHeader(headers, "x-amz-version-id", object.getVersionId());
            }
            return new OriginResponse(204, null, null, 0, headers);
        } catch (AwsException e) {
            return OriginResponse.error(e.getHttpStatus(), e.getMessage());
        }
    }

    private OriginResponse postToS3(
            Origin origin, String key, String rawQuery, byte[] requestBody,
            HttpHeaders requestHeaders, UriInfo uriInfo) {
        String bucket = CloudFrontRequestRouter.bucketFromS3Domain(origin.getDomainName());
        if (bucket == null) {
            return OriginResponse.error(502, "Could not determine S3 bucket for origin.");
        }
        try {
            Response response;
            if (key == null || key.isEmpty()) {
                response = s3Controller.handleForwardedBucketPost(
                        bucket, requestHeaders.getHeaderString("Content-Type"),
                        rawQuery, requestBody != null ? requestBody : new byte[0]);
            } else {
                response = s3Controller.handleForwardedObjectPost(
                        bucket,
                        key,
                        firstQueryValue(uriInfo, "uploadId"),
                        firstQueryValue(uriInfo, "versionId"),
                        requestHeaders.getHeaderString("Content-Type"),
                        requestHeaders.getHeaderString("If-Match"),
                        requestHeaders.getHeaderString("If-None-Match"),
                        requestHeaders,
                        uriInfo,
                        rawQuery,
                        requestBody != null ? requestBody : new byte[0],
                        "https://" + origin.getDomainName() + "/");
            }
            return fromS3Response(response);
        } catch (RuntimeException e) {
            return fromS3Response(s3Controller.mapUnhandledThrowable(e));
        }
    }

    private OriginResponse patchToS3(Origin origin, String key) {
        String bucket = CloudFrontRequestRouter.bucketFromS3Domain(origin.getDomainName());
        if (bucket == null) {
            return OriginResponse.error(502, "Could not determine S3 bucket for origin.");
        }
        Response response = key == null || key.isEmpty()
                ? s3Controller.handleBucketPatch(bucket)
                : s3Controller.handleObjectPatch(bucket, key);
        return fromS3Response(response);
    }

    private static String firstQueryValue(UriInfo uriInfo, String name) {
        return uriInfo.getQueryParameters().getFirst(name);
    }

    private static OriginResponse fromS3Response(Response response) {
        Object entity = response.getEntity();
        byte[] body;
        if (entity == null) {
            body = new byte[0];
        } else if (entity instanceof byte[] bytes) {
            body = bytes;
        } else {
            body = entity.toString().getBytes(StandardCharsets.UTF_8);
        }
        Map<String, List<String>> headers = new LinkedHashMap<>();
        response.getStringHeaders().forEach(
                (name, values) -> headers.put(name, List.copyOf(values)));
        String contentType = response.getMediaType() != null
                ? response.getMediaType().toString()
                : response.getHeaderString("Content-Type");
        return new OriginResponse(
                response.getStatus(), contentType, body, body.length, headers);
    }

    private OriginResponse fetchS3Preflight(Origin origin, String viewerOrigin,
                                            String requestMethod, String requestHeaders) {
        String bucket = CloudFrontRequestRouter.bucketFromS3Domain(origin.getDomainName());
        if (bucket == null) {
            return OriginResponse.error(502, "Could not determine S3 bucket for origin.");
        }
        if (viewerOrigin == null || viewerOrigin.isBlank()
                || requestMethod == null || requestMethod.isBlank()) {
            return new OriginResponse(200, null, new byte[0], 0, Map.of());
        }
        List<String> requestedHeaders = splitHeaderValues(requestHeaders);
        return s3Service.evaluateCors(bucket, viewerOrigin, requestMethod, requestedHeaders)
                .map(cors -> {
                    Map<String, List<String>> headers = new LinkedHashMap<>();
                    putHeader(headers, "Access-Control-Allow-Origin", cors.allowedOrigin());
                    putHeader(headers, "Access-Control-Allow-Methods",
                            String.join(", ", cors.allowedMethods()));
                    if (cors.maxAgeSeconds() > 0) {
                        putHeader(headers, "Access-Control-Max-Age",
                                Integer.toString(cors.maxAgeSeconds()));
                    }
                    if (!cors.allowedHeaders().isEmpty()) {
                        putHeader(headers, "Access-Control-Allow-Headers",
                                String.join(", ", cors.allowedHeaders()));
                    }
                    if (!cors.exposeHeaders().isEmpty()) {
                        putHeader(headers, "Access-Control-Expose-Headers",
                                String.join(", ", cors.exposeHeaders()));
                    }
                    return new OriginResponse(200, null, new byte[0], 0, headers);
                })
                .orElseGet(() -> OriginResponse.error(403,
                        "This CORS request is not allowed."));
    }

    /** Fetches from a custom (non-S3) origin. {@code forwardUri} already includes the origin path. */
    private OriginResponse fetchFromCustomOrigin(Origin origin, String forwardUri, String rawQuery,
                                                 String viewerScheme, String method,
                                                 String viewerOrigin,
                                                 String accessControlRequestMethod,
                                                 String accessControlRequestHeaders,
                                                 byte[] requestBody,
                                                 Map<String, String> viewerHeaders) {
        boolean includeBody = !"HEAD".equals(method);
        try {
            URI target = buildCustomOriginUri(
                    origin, viewerScheme, forwardUri, rawQuery);
            HttpRequest.Builder rb = HttpRequest.newBuilder()
                    .uri(target)
                    .timeout(Duration.ofSeconds(30));
            // Origin custom headers: CloudFront adds these to every request it forwards to the origin
            // (overriding any same-named viewer header), which is how a distribution restricts an origin
            // to CloudFront-only traffic via a shared secret header.
            Map<String, String> originHeaders = new LinkedHashMap<>();
            List<Map<String, String>> customHeaders = origin.getCustomHeaders();
            if (customHeaders != null) {
                for (Map<String, String> header : customHeaders) {
                    String name = header.get("HeaderName");
                    String value = header.get("HeaderValue");
                    if (name != null && value != null) {
                        originHeaders.put(name, value);
                    }
                }
            }
            rb.method(method, requestBody != null
                    ? HttpRequest.BodyPublishers.ofByteArray(requestBody)
                    : HttpRequest.BodyPublishers.noBody());
            if (viewerHeaders != null) {
                viewerHeaders.forEach((name, value) -> addRequestHeader(rb, name, value));
            }
            if ("OPTIONS".equals(method)) {
                addRequestHeader(rb, "Origin", viewerOrigin);
                addRequestHeader(rb, "Access-Control-Request-Method", accessControlRequestMethod);
                addRequestHeader(rb, "Access-Control-Request-Headers", accessControlRequestHeaders);
            }
            HttpResponse<byte[]> resp = httpClient.send(
                    rb.build(), originHeaders, requestBody,
                    HttpResponse.BodyHandlers.ofByteArray());
            String ct = resp.headers().firstValue("content-type").orElse(DEFAULT_CONTENT_TYPE);
            byte[] body = resp.body() != null ? resp.body() : new byte[0];
            long contentLength = includeBody ? body.length : responseContentLength(resp);
            return new OriginResponse(resp.statusCode(), ct, includeBody ? body : null,
                    contentLength, resp.headers().map());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOG.warnv("CloudFront custom origin fetch was interrupted for host {0}",
                    safeOriginName(origin));
            return OriginResponse.error(502, "Bad Gateway.");
        } catch (Exception e) {
            // Do not log the target URI: forwarded query strings can contain credentials or tokens.
            LOG.warnv("CloudFront custom origin fetch failed for host {0}: {1}",
                    safeOriginName(origin), e.getClass().getSimpleName());
            return OriginResponse.error(502, "Bad Gateway.");
        }
    }

    static boolean isBlockedOriginAddress(InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress()
                || address.isLinkLocalAddress() || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return true;
        }
        byte[] bytes = address.getAddress();
        if (bytes.length == 4) {
            return isBlockedIpv4Address(bytes, 0);
        }
        if (bytes.length == 16) {
            if (isIpv4MappedAddress(bytes)) {
                return isBlockedIpv4Address(bytes, 12);
            }
            int first = Byte.toUnsignedInt(bytes[0]);
            boolean uniqueLocal = (first & 0xfe) == 0xfc;
            boolean documentation = first == 0x20
                    && Byte.toUnsignedInt(bytes[1]) == 0x01
                    && Byte.toUnsignedInt(bytes[2]) == 0x0d
                    && Byte.toUnsignedInt(bytes[3]) == 0xb8;
            return uniqueLocal || documentation;
        }
        return true;
    }

    private static boolean isIpv4MappedAddress(byte[] bytes) {
        for (int i = 0; i < 10; i++) {
            if (bytes[i] != 0) {
                return false;
            }
        }
        return bytes[10] == (byte) 0xff && bytes[11] == (byte) 0xff;
    }

    private static boolean isBlockedIpv4Address(byte[] bytes, int offset) {
        int first = Byte.toUnsignedInt(bytes[offset]);
        int second = Byte.toUnsignedInt(bytes[offset + 1]);
        int third = Byte.toUnsignedInt(bytes[offset + 2]);
        return first == 0
                || first == 10
                || first == 127
                || (first == 100 && second >= 64 && second <= 127)
                || (first == 169 && second == 254)
                || (first == 172 && second >= 16 && second <= 31)
                || (first == 192 && second == 168)
                || (first == 192 && second == 0 && third == 0)
                || (first == 192 && second == 0 && third == 2)
                || (first == 198 && (second == 18 || second == 19))
                || (first == 198 && second == 51 && third == 100)
                || (first == 203 && second == 0 && third == 113)
                || first >= 224;
    }

    static URI buildCustomOriginUri(String protocol, String domainName, int port,
                                    String forwardUri, String rawQuery) {
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("Custom origin port is outside the valid range");
        }
        String host = normalizeOriginHost(domainName);
        String path = forwardUri == null || forwardUri.isBlank() ? "/" : forwardUri;
        if (!path.startsWith("/") || path.indexOf('?') >= 0 || path.indexOf('#') >= 0) {
            throw new IllegalArgumentException("Custom origin path is invalid");
        }
        String authorityHost = host.indexOf(':') >= 0 ? "[" + host + "]" : host;
        return URI.create(protocol + "://" + authorityHost + ":" + port + path
                + (rawQuery == null || rawQuery.isEmpty() ? "" : "?" + rawQuery));
    }

    static URI buildCustomOriginUri(Origin origin, String viewerScheme,
                                    String forwardUri, String rawQuery) {
        Map<String, Object> config = origin.getCustomOriginConfig();
        String policy = config != null ? str(config.get("OriginProtocolPolicy")) : "";
        boolean useHttps = "https-only".equalsIgnoreCase(policy)
                || ("match-viewer".equalsIgnoreCase(policy)
                        && "https".equalsIgnoreCase(viewerScheme));
        String protocol = useHttps ? "https" : "http";
        int port = useHttps
                ? intOrDefault(config, "HTTPSPort", 443)
                : intOrDefault(config, "HTTPPort", 80);
        URI authority = URI.create("//" + origin.getDomainName().trim());
        if (authority.getPort() >= 0 && isEmulatorLocalOrigin(authority.getHost())) {
            port = authority.getPort();
        }
        return buildCustomOriginUri(
                protocol, origin.getDomainName(), port, forwardUri, rawQuery);
    }

    private static boolean isEmulatorLocalOrigin(String host) {
        if (host == null) {
            return false;
        }
        String normalized = normalizeHost(host);
        return normalized.endsWith(".localhost.floci.io")
                || normalized.endsWith(".localhost.localstack.cloud");
    }

    static String rawViewerPath(String requestUri) {
        if (requestUri == null || requestUri.isBlank()) {
            return "/";
        }
        int query = requestUri.indexOf('?');
        String path = query >= 0 ? requestUri.substring(0, query) : requestUri;
        if (path.startsWith("http://") || path.startsWith("https://")) {
            path = URI.create(path).getRawPath();
        }
        if (path == null || path.isEmpty()) {
            return "/";
        }
        return path.startsWith("/") ? path : "/" + path;
    }

    static String decodedViewerPath(String rawViewerPath) {
        return URI.create("http://viewer.invalid" + rawViewerPath).getPath();
    }

    static String normalizeOriginHost(String domainName) {
        if (domainName == null || domainName.isBlank()) {
            throw new IllegalArgumentException("Custom origin domain name is empty");
        }
        URI authority = URI.create("//" + domainName.trim());
        if (authority.getRawUserInfo() != null
                || (authority.getRawPath() != null && !authority.getRawPath().isEmpty())
                || authority.getRawQuery() != null || authority.getRawFragment() != null
                || authority.getHost() == null) {
            throw new IllegalArgumentException("Custom origin domain name is not a valid authority");
        }
        return normalizeHost(authority.getHost());
    }

    static String normalizeHost(String host) {
        String normalized = host.trim();
        if (normalized.startsWith("[") && normalized.endsWith("]")) {
            normalized = normalized.substring(1, normalized.length() - 1);
        }
        while (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("Custom origin host is empty");
        }
        if (normalized.indexOf(':') < 0) {
            normalized = IDN.toASCII(normalized);
        }
        return normalized.toLowerCase(Locale.ROOT);
    }

    private static long responseContentLength(HttpResponse<?> response) {
        try {
            return response.headers().firstValueAsLong("content-length").orElse(-1L);
        } catch (NumberFormatException e) {
            LOG.debugv("Ignoring invalid custom-origin Content-Length: {0}", e.getMessage());
            return -1L;
        }
    }

    private static String safeOriginName(Origin origin) {
        try {
            return normalizeOriginHost(origin.getDomainName());
        } catch (RuntimeException e) {
            return "<invalid>";
        }
    }

    /**
     * Applies a matching {@code CustomErrorResponse} to an origin error, per the AWS CloudFront spec.
     * Returns {@code null} when no custom handling applies, so the caller returns the original origin
     * response unchanged. Otherwise:
     *
     * <ul>
     *   <li>with no {@code ResponsePagePath}, the origin body is kept but the status is overridden by
     *       {@code ResponseCode};</li>
     *   <li>with a {@code ResponsePagePath}, the page is fetched through behavior/origin routing and,
     *       on success, returned with {@code ResponseCode} (the single-page-app 403/404 -&gt; 200
     *       {@code /index.html} fallback);</li>
     *   <li>if the custom error page is itself unavailable, CloudFront returns the status code it
     *       received from the origin that holds the error pages — not the original status — and does
     *       not recurse (no loop).</li>
     * </ul>
     */
    private Response applyCustomError(DistributionConfig config, OriginResponse origin,
                                      String viewerScheme, boolean includeBody,
                                      ResponseHeadersPolicyConfigCodec.Directives directives) {
        Map<String, Object> cer = matchCustomError(config, origin.status());
        if (cer == null) {
            return null;
        }
        int responseCode = parseIntOr(cer.get("ResponseCode"), origin.status());
        String pagePath = str(cer.get("ResponsePagePath"));
        if (pagePath.isBlank()) {
            // ResponseCode override with no custom page: keep the origin body, change the status.
            return toResponse(new OriginResponse(responseCode, origin.contentType(), origin.body(),
                    origin.contentLength(), origin.headers()), includeBody, directives);
        }

        String errNormalized = CloudFrontRequestRouter.normalizePath(pagePath);
        String errOriginId = CloudFrontRequestRouter.matchTargetOriginId(config, errNormalized);
        Origin errOrigin = CloudFrontRequestRouter.findOrigin(config, errOriginId);
        if (errOrigin == null) {
            return null;
        }

        OriginResponse page;
        if (CloudFrontRequestRouter.isS3Origin(errOrigin)) {
            String key = CloudFrontRequestRouter.resolveOriginKey(errOrigin.getOriginPath(), errNormalized, null);
            page = fetchFromS3(errOrigin, key, includeBody);
        } else {
            String forwardUri = CloudFrontRequestRouter.resolveForwardUri(errOrigin.getOriginPath(), errNormalized, null);
            page = fetchFromCustomOrigin(
                    errOrigin, forwardUri, null, viewerScheme, includeBody ? "GET" : "HEAD",
                    null, null, null, null, Map.of());
        }
        if (page.status() >= 400) {
            // Custom error page unavailable → return the status received from the error-page origin
            // (AWS behavior), without recursively applying custom error handling.
            return toResponse(page, includeBody, directives);
        }
        return toResponse(new OriginResponse(responseCode, page.contentType(), page.body(),
                page.contentLength(), page.headers()), includeBody, directives);
    }

    private Map<String, Object> matchCustomError(DistributionConfig config, int status) {
        List<Map<String, Object>> list = config.getCustomErrorResponses();
        if (list == null) {
            return null;
        }
        for (Map<String, Object> cer : list) {
            if (parseIntOr(cer.get("ErrorCode"), -1) == status) {
                return cer;
            }
        }
        return null;
    }

    private Response toResponse(OriginResponse origin, boolean includeBody,
                                ResponseHeadersPolicyConfigCodec.Directives directives) {
        Response.ResponseBuilder rb = Response.status(origin.status());
        HeaderCollection collected = collectResponseHeaders(origin, includeBody);
        applyResponseHeadersPolicy(
                collected.headers(), directives, collected.forbiddenPolicyHeaders());
        for (HeaderValues header : collected.headers().values()) {
            header.values().forEach(value -> rb.header(header.name(), value));
        }
        if (includeBody && origin.body() != null) {
            rb.entity(origin.body());
        }
        return rb.build();
    }

    /**
     * Collects end-to-end origin headers case-insensitively while preserving every value. Hop-by-hop
     * fields and fields named by the origin's {@code Connection} header are omitted.
     */
    private static HeaderCollection collectResponseHeaders(
            OriginResponse origin, boolean includeBody) {
        Set<String> excludedOriginHeaders = new HashSet<>(NON_FORWARDED_RESPONSE_HEADERS);
        Set<String> forbiddenPolicyHeaders = new HashSet<>(FORBIDDEN_POLICY_RESPONSE_HEADERS);
        origin.headers().forEach((name, values) -> {
            if ("connection".equalsIgnoreCase(name)) {
                values.forEach(value -> {
                    for (String token : value.split(",")) {
                        String normalized = normalizeHeaderName(token);
                        if (!normalized.isEmpty()) {
                            excludedOriginHeaders.add(normalized);
                            forbiddenPolicyHeaders.add(normalized);
                        }
                    }
                });
            }
        });

        Map<String, HeaderValues> headers = new LinkedHashMap<>();
        origin.headers().forEach((name, values) -> {
            String normalized = normalizeHeaderName(name);
            if (!normalized.isEmpty() && !excludedOriginHeaders.contains(normalized)) {
                HeaderValues existing = headers.computeIfAbsent(normalized,
                        ignored -> new HeaderValues(name, new ArrayList<>()));
                existing.values().addAll(values);
            }
        });
        if (origin.contentType() != null) {
            setHeader(headers, "Content-Type", origin.contentType());
        }
        if (!includeBody && origin.contentLength() >= 0) {
            setHeader(headers, "Content-Length", Long.toString(origin.contentLength()));
        }
        return new HeaderCollection(headers, forbiddenPolicyHeaders);
    }

    /** Applies removals first, then policy additions with their origin-override semantics. */
    private static void applyResponseHeadersPolicy(
            Map<String, HeaderValues> headers,
            ResponseHeadersPolicyConfigCodec.Directives directives,
            Set<String> forbiddenPolicyHeaders) {
        if (directives == null) {
            return;
        }
        boolean replaceServer = false;
        boolean replaceDate = false;
        for (String name : directives.remove()) {
            String normalized = normalizeHeaderName(name);
            if (ResponseHeadersPolicyValidator.isForbiddenRemoval(normalized)) {
                continue;
            }
            headers.remove(normalized);
            replaceServer |= "server".equals(normalized);
            replaceDate |= "date".equals(normalized);
        }
        if (replaceServer) {
            setHeader(headers, "Server", "CloudFront");
        }
        if (replaceDate) {
            setHeader(headers, "Date", HTTP_DATE.format(Instant.now()));
        }
        boolean hasOriginCorsHeader = headers.keySet().stream()
                .anyMatch(CloudFrontServingController::isCorsHeader);
        for (ResponseHeadersPolicyConfigCodec.PolicyHeader header : directives.add()) {
            String normalized = normalizeHeaderName(header.name());
            if (normalized.isEmpty() || forbiddenPolicyHeaders.contains(normalized)) {
                continue;
            }
            if (isCorsHeader(normalized) && !header.override() && hasOriginCorsHeader) {
                continue;
            }
            if (header.override() || !headers.containsKey(normalized)) {
                setHeader(headers, header.name(), header.value());
            }
        }
    }

    private static void setHeader(
            Map<String, HeaderValues> headers, String name, String value) {
        headers.put(normalizeHeaderName(name),
                new HeaderValues(name, new ArrayList<>(List.of(value == null ? "" : value))));
    }

    private static String normalizeHeaderName(String name) {
        return name == null ? "" : name.trim().toLowerCase(Locale.ROOT);
    }

    private static boolean isCorsHeader(String name) {
        return normalizeHeaderName(name).startsWith("access-control-");
    }

    private Response textError(int status, String message) {
        return Response.status(status)
                .type(MediaType.TEXT_PLAIN)
                .entity(message == null ? "" : message)
                .build();
    }

    private static String contentType(S3Object obj) {
        return obj.getContentType() != null ? obj.getContentType() : DEFAULT_CONTENT_TYPE;
    }

    private static Map<String, List<String>> s3ObjectHeaders(S3Object object) {
        Map<String, List<String>> headers = new LinkedHashMap<>();
        putHeader(headers, "Accept-Ranges", "bytes");
        putHeader(headers, "ETag", object.getETag());
        if (object.getLastModified() != null) {
            putHeader(headers, "Last-Modified", HTTP_DATE.format(object.getLastModified()));
        }
        putHeader(headers, "Cache-Control", object.getCacheControl());
        putHeader(headers, "Content-Encoding", object.getContentEncoding());
        putHeader(headers, "Content-Disposition", object.getContentDisposition());
        putHeader(headers, "x-amz-storage-class", object.getStorageClass());
        if (object.getMetadata() != null) {
            object.getMetadata().forEach((name, value) ->
                    putHeader(headers, "x-amz-meta-" + name, value));
        }
        return headers;
    }

    private static void putHeader(Map<String, List<String>> headers, String name, String value) {
        if (value != null) {
            headers.put(name, List.of(value));
        }
    }

    private static Map<String, String> viewerHeaders(HttpHeaders headers) {
        Map<String, String> forwarded = new LinkedHashMap<>();
        for (String name : List.of(
                "Content-Type", "Accept", "Authorization", "X-Correlation-Id",
                "X-Amzn-Trace-Id", "traceparent", "tracestate", "baggage")) {
            String value = headers.getHeaderString(name);
            if (value != null && !value.isBlank()) {
                forwarded.put(name, value);
            }
        }
        return forwarded;
    }

    private static List<String> splitHeaderValues(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        List<String> values = new ArrayList<>();
        for (String item : value.split(",")) {
            String trimmed = item.trim();
            if (!trimmed.isEmpty()) {
                values.add(trimmed);
            }
        }
        return values;
    }

    private static void addRequestHeader(HttpRequest.Builder request, String name, String value) {
        if (value != null && !value.isBlank()) {
            request.header(name, value);
        }
    }

    private static String str(Object value) {
        return value != null ? value.toString() : "";
    }

    private static int intOrDefault(Map<String, Object> map, String key, int dflt) {
        return map == null ? dflt : parseIntOr(map.get(key), dflt);
    }

    private static int parseIntOr(Object value, int dflt) {
        if (value == null) {
            return dflt;
        }
        try {
            return Integer.parseInt(value.toString().trim());
        } catch (NumberFormatException e) {
            LOG.debugv("Ignoring non-integer CloudFront configuration value {0}: {1}", value, e.getMessage());
            return dflt;
        }
    }

    private record HeaderValues(String name, List<String> values) {
    }

    private record HeaderCollection(Map<String, HeaderValues> headers,
                                    Set<String> forbiddenPolicyHeaders) {
    }

    /** The result of fetching from an origin, including end-to-end response headers. */
    private record OriginResponse(int status, String contentType, byte[] body, long contentLength,
                                  Map<String, List<String>> headers) {
        static OriginResponse error(int status, String message) {
            byte[] b = message == null ? new byte[0] : message.getBytes(StandardCharsets.UTF_8);
            return new OriginResponse(status, MediaType.TEXT_PLAIN, b, b.length, Map.of());
        }
    }
}
