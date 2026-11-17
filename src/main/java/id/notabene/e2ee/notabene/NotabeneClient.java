package id.notabene.e2ee.notabene;

import id.notabene.e2ee.config.NotabeneProperties;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * Minimal Notabene v2.1 REST client - just the calls this project needs.
 * Every path is /api/v1/...; the credential identifies the node, so there is no
 * entity DID in any URL any more.
 *
 * Customers: https://devx.notabene.id/v2.1/reference/post_api-v1-customers
 * Wallets:   https://devx.notabene.id/v2.1/reference/post_api-v1-wallets
 * Proofs:    https://devx.notabene.id/v2.1/reference/post_api-v1-customers-customer-wallets-address-proofs
 * Discovery: https://devx.notabene.id/v2.1/reference/post_api-v1-wallet-ownerships-discover
 * Transfers: https://devx.notabene.id/v2.1/reference/post_api-v1-transfers
 */
@Service
@Slf4j
public class NotabeneClient {

    private final NotabeneProperties properties;
    private final TokenService tokenService;
    private final ObjectMapper json;
    private final RestClient restClient;

    public NotabeneClient(NotabeneProperties properties, TokenService tokenService, ObjectMapper json,
            RestClient.Builder builder) {
        this.properties = properties;
        this.tokenService = tokenService;
        this.json = json;
        // Handle error statuses ourselves so callers can act on 404/409.
        this.restClient = builder
                .defaultStatusHandler(HttpStatusCode::isError, (request, response) -> {
                })
                .build();
    }

    // ---------------------------------------------------------------- customers & wallets

    /** POST /api/v1/customers. 409 "customer already exists" is not an error here. */
    public void ensureCustomer(NotabeneProperties.Vasp caller, Map<String, Object> body) {
        try {
            request(caller, "POST", "/api/v1/customers", body);
        } catch (NotabeneApiException e) {
            if (e.getStatus() != 409) {
                throw e;
            }
            log.debug("customer {} already exists", body.get("id"));
        }
    }

    /**
     * POST /api/v1/wallets. Registering the same wallet again is a 201; the same
     * address under different details is a 409.
     */
    public Map<String, Object> registerWallet(NotabeneProperties.Vasp caller, Map<String, Object> body) {
        return request(caller, "POST", "/api/v1/wallets", body);
    }

    /** POST /api/v1/customers/{customer}/wallets/{address}/proofs - 201 with the stored proof. */
    public Map<String, Object> submitWalletProof(NotabeneProperties.Vasp caller, String customer, String caip10,
            Map<String, Object> body) {
        return request(caller, "POST",
                "/api/v1/customers/" + encode(customer) + "/wallets/" + encode(caip10) + "/proofs", body);
    }

    /**
     * POST /api/v1/wallet-ownerships/discover. Returns owner, custodian and
     * source, or null when nothing owns the address (a 404, which is the answer
     * to the question rather than an error).
     */
    public Map<String, Object> discoverWalletOwnership(NotabeneProperties.Vasp caller, String caip10) {
        try {
            return request(caller, "POST", "/api/v1/wallet-ownerships/discover", Map.of("address", caip10));
        } catch (NotabeneApiException e) {
            if (e.getStatus() == 404) {
                return null;
            }
            throw e;
        }
    }

    /** GET /api/v1/network/entities/{did}: name and jurisdiction, no key material. */
    public Map<String, Object> getNetworkEntity(NotabeneProperties.Vasp caller, String did) {
        return request(caller, "GET", "/api/v1/network/entities/" + encode(did), null);
    }

    // ---------------------------------------------------------------- transfers

    /**
     * The counterparty's PII encryption key. v2.1 has no public-keys endpoint;
     * the assess call returns beneficiaryVasp.encryptionKey when asked.
     */
    public Map<String, Object> assessTransfer(NotabeneProperties.Vasp caller, String asset, String amount,
            String destinationAddress) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("asset", asset);
        body.put("amount", amount);
        body.put("destinationAddress", destinationAddress);
        return request(caller, "POST", "/api/v1/transfers/assess?include_pubkeys=true", body);
    }

    /** POST /api/v1/transfers - answers {transferId, status}. */
    public Map<String, Object> createTransfer(NotabeneProperties.Vasp caller, Map<String, Object> body) {
        return request(caller, "POST", "/api/v1/transfers", body);
    }

    /** include_ivms=true adds each party's ivms_encrypted JWE (needs read:customer:pii). */
    public Map<String, Object> getTransfer(NotabeneProperties.Vasp caller, String transferId, boolean includeIvms) {
        return request(caller, "GET", "/api/v1/transfers/" + encode(transferId) + "?include_ivms=" + includeIvms,
                null);
    }

    /** GET /api/v1/transfers - used by the poller to spot new incoming transfers. */
    public List<Map<String, Object>> listTransfers(NotabeneProperties.Vasp caller, String direction, int limit) {
        StringBuilder query = new StringBuilder("?limit=").append(Math.max(1, Math.min(limit, 200)));
        if (direction != null && !direction.isBlank()) {
            // The API's enum is Incoming | Outgoing.
            String d = direction.trim().toLowerCase();
            query.append("&direction=").append(Character.toUpperCase(d.charAt(0))).append(d.substring(1));
        }
        Map<String, Object> response = request(caller, "GET", "/api/v1/transfers" + query, null);

        List<Map<String, Object>> out = new ArrayList<>();
        if (response.get("items") instanceof List<?> list) {
            for (Object item : list) {
                if (item instanceof Map<?, ?> map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> typed = (Map<String, Object>) map;
                    out.add(typed);
                }
            }
        }
        return out;
    }

    /**
     * POST /api/v1/transfers/{id}/parties/{role}/encrypted-pii. Role is
     * "originator" or "beneficiary"; the body is one compact JWE. 204 means it
     * was disclosed to the recipient, 202 that a compliance hold has it.
     */
    public Map<String, Object> addEncryptedPii(NotabeneProperties.Vasp caller, String transferId, String role,
            String jwe) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ivms_encrypted", jwe);
        return request(caller, "POST",
                "/api/v1/transfers/" + encode(transferId) + "/parties/" + encode(role) + "/encrypted-pii", body);
    }

    // ---------------------------------------------------------------- plumbing

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
            // 204 and friends: the status is the whole answer.
            return Map.of("httpStatus", response.getStatusCode().value());
        }
        if (!text.trim().startsWith("{")) {
            Map<String, Object> wrapped = new LinkedHashMap<>();
            wrapped.put("raw", text);
            return wrapped;
        }
        return json.readValue(text, Map.class);
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
