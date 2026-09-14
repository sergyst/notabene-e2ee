package id.notabene.e2ee.notabene;

import id.notabene.e2ee.config.NotabeneProperties;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * Minimal Notabene Transact V2 REST client - just the calls this project needs.
 *
 * Transfers: https://devx.notabene.id/reference/createtransfer
 * PII:       https://devx.notabene.id/reference/presenttransferpii
 * Keys:      https://devx.notabene.id/reference/getentitypublickeys
 */
@Service
public class NotabeneClient {

    private static final Logger log = LoggerFactory.getLogger(NotabeneClient.class);

    private final NotabeneProperties properties;
    private final TokenService tokenService;
    private final ObjectMapper json;
    private final RestClient restClient;

    public NotabeneClient(NotabeneProperties properties, TokenService tokenService, ObjectMapper json,
            RestClient.Builder builder) {
        this.properties = properties;
        this.tokenService = tokenService;
        this.json = json;
        // Handle error statuses ourselves so we can fall through to the next
        // documented path spelling on a 404/405.
        this.restClient = builder
                .defaultStatusHandler(HttpStatusCode::isError, (request, response) -> {
                })
                .build();
    }

    /**
     * The counterparty's PII encryption key. Notabene's priority is "#pii"
     * first, so a published EcdsaSecp256r1VerificationKey2019 wins.
     */
    public Map<String, Object> getEntityPublicKeys(NotabeneProperties.Vasp caller, String entityDid) {
        String did = encode(entityDid);
        return getMap(caller, List.of(
                "/entities/" + did + "/public-keys",
                "/entity/" + did + "/public-keys"));
    }

    public Map<String, Object> createTransfer(NotabeneProperties.Vasp caller, Map<String, Object> body) {
        String did = encode(caller.getDid());
        return requestFirstThatWorks(caller, "POST", List.of(
                "/entities/" + did + "/tx",
                "/entity/" + did + "/tx"), body);
    }

    public Map<String, Object> getTransfer(NotabeneProperties.Vasp caller, String transferId, boolean decrypt) {
        String did = encode(caller.getDid());
        String query = "?decrypt=" + decrypt;
        return getMap(caller, List.of(
                "/entities/" + did + "/tx/" + transferId + query,
                "/entity/" + did + "/tx/" + transferId + query));
    }

    /** GET /entities/:did/tx - used by the poller to spot new incoming transfers. */
    public List<Map<String, Object>> listTransfers(NotabeneProperties.Vasp caller, String direction, int limit) {
        String did = encode(caller.getDid());
        StringBuilder query = new StringBuilder("?limit=").append(limit);
        if (direction != null && !direction.isBlank()) {
            query.append("&direction=").append(encode(direction));
        }

        Map<String, Object> response;
        try {
            response = getMap(caller, List.of(
                    "/entities/" + did + "/tx" + query,
                    "/entity/" + did + "/tx" + query));
        } catch (NotabeneApiException e) {
            // Some nodes reject the direction filter; retry without it rather
            // than killing the poll loop.
            if (direction == null || direction.isBlank() || e.getStatus() != 400) {
                throw e;
            }
            log.debug("direction={} rejected ({}), retrying without the filter", direction, e.getStatus());
            response = getMap(caller, List.of(
                    "/entities/" + did + "/tx?limit=" + limit,
                    "/entity/" + did + "/tx?limit=" + limit));
        }

        Object data = response.get("data");
        if (data instanceof List<?> list) {
            List<Map<String, Object>> out = new ArrayList<>();
            for (Object item : list) {
                if (item instanceof Map<?, ?> map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> typed = (Map<String, Object>) map;
                    out.add(typed);
                }
            }
            return out;
        }
        return List.of();
    }

    /**
     * Which VASP owns a blockchain address, per relationships, the Hashed
     * Address Service and blockchain analytics.
     * https://devx.notabene.id/reference/discoveraddressownership
     */
    public Map<String, Object> discoverAddressOwnership(NotabeneProperties.Vasp caller, String asset, String address) {
        String did = encode(caller.getDid());
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("asset", asset);
        body.put("address", address);
        try {
            return requestFirstThatWorks(caller, "POST", List.of(
                    "/entities/" + did + "/address-ownership/discover",
                    "/entity/" + did + "/address-ownership/discover"), body);
        } catch (NotabeneApiException e) {
            // Notabene answers 404 with a complete body when nothing owns the
            // address. "NOT_FOUND" is the answer to the question, not an error.
            if (e.getStatus() == 404 && e.getBody() != null && e.getBody().contains("\"addressOwnership\"")) {
                return parse(e.getBody());
            }
            throw e;
        }
    }

    /**
     * Claim an address for an entity. PATCH upserts, so it both creates the
     * relationship and confirms it.
     * https://devx.notabene.id/reference/confirmrelationship
     */
    public Map<String, Object> confirmRelationship(NotabeneProperties.Vasp caller, String from, String to) {
        String did = encode(caller.getDid());
        String query = "?from=" + encode(from) + "&to=" + encode(to);
        return requestFirstThatWorks(caller, "PATCH", List.of(
                "/entities/" + did + "/relationships" + query,
                "/entity/" + did + "/relationships" + query), Map.of());
    }

    /** Everything this entity knows about who owns which address. */
    public Map<String, Object> listRelationships(NotabeneProperties.Vasp caller) {
        String did = encode(caller.getDid());
        return getMap(caller, List.of(
                "/entities/" + did + "/relationships",
                "/entity/" + did + "/relationships"));
    }

    /**
     * Post the already-encrypted IVMS101 to the counterparty. With a policyId it
     * fulfils that specific policy; without one it fulfils any open Travel Rule
     * policy on the transfer.
     */
    public Map<String, Object> presentPii(NotabeneProperties.Vasp caller, String transferId, Object ivms101,
            String policyId) {
        String did = encode(caller.getDid());
        String query = "?skipValidation=" + properties.isSkipValidation();

        List<String> paths = (policyId == null || policyId.isBlank())
                ? List.of(
                        "/entities/" + did + "/tx/" + transferId + "/presentation" + query,
                        "/entity/" + did + "/tx/" + transferId + "/presentation" + query,
                        "/entities/" + did + "/transfers/" + transferId + "/presentation" + query)
                : List.of(
                        "/entities/" + did + "/transfers/" + transferId + "/policies/" + policyId + "/presentation" + query,
                        "/entities/" + did + "/tx/" + transferId + "/policy/" + policyId + "/presentation" + query,
                        "/entity/" + did + "/tx/" + transferId + "/policy/" + policyId + "/presentation" + query);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ivms101", ivms101);
        return requestFirstThatWorks(caller, "POST", paths, body);
    }

    // ---------------------------------------------------------------- plumbing

    private Map<String, Object> getMap(NotabeneProperties.Vasp caller, List<String> paths) {
        return requestFirstThatWorks(caller, "GET", paths, null);
    }

    /** Notabene's prose docs and OpenAPI spec disagree on path spellings. */
    private Map<String, Object> requestFirstThatWorks(NotabeneProperties.Vasp caller, String method,
            List<String> paths, Object body) {
        NotabeneApiException lastError = null;
        for (String path : paths) {
            try {
                Map<String, Object> result = request(caller, method, path, body);
                log.info("used {} {}", method, path.split("\\?")[0]);
                return result;
            } catch (NotabeneApiException e) {
                if (e.getStatus() != 404 && e.getStatus() != 405) {
                    throw e;
                }
                log.debug("{} {} -> {}, trying next spelling", method, path.split("\\?")[0], e.getStatus());
                lastError = e;
            }
        }
        throw lastError != null ? lastError
                : new NotabeneApiException("No path candidates were tried", 500, "");
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> request(NotabeneProperties.Vasp caller, String method, String path, Object body) {
        String token = tokenService.accessToken(caller);
        String url = properties.getApiBase() + path;

        RestClient.RequestBodySpec spec = restClient
                .method(org.springframework.http.HttpMethod.valueOf(method))
                // URI.create, not the String overload: the path already carries
                // percent-encoded DIDs and must not be treated as a template.
                .uri(URI.create(url))
                .header("Authorization", "Bearer " + token);

        RestClient.RequestHeadersSpec<?> ready = (body == null)
                ? spec
                : spec.contentType(MediaType.APPLICATION_JSON).body(body);

        ResponseEntity<String> response = ready.retrieve().toEntity(String.class);

        String text = response.getBody() == null ? "" : response.getBody();
        if (response.getStatusCode().isError()) {
            throw new NotabeneApiException(
                    method + " " + path + " -> " + response.getStatusCode().value() + ": "
                            + text.substring(0, Math.min(text.length(), 600)),
                    response.getStatusCode().value(), text);
        }

        if (text.isBlank()) {
            return Map.of();
        }
        if (!text.trim().startsWith("{")) {
            Map<String, Object> wrapped = new LinkedHashMap<>();
            wrapped.put("raw", text);
            return wrapped;
        }
        return json.readValue(text, Map.class);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> parse(String text) {
        return json.readValue(text, Map.class);
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
