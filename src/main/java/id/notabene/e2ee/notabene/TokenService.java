package id.notabene.e2ee.notabene;

import id.notabene.e2ee.config.NotabeneProperties;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

/**
 * OAuth2 client-credentials tokens, cached per clientId until shortly before
 * they expire. https://devx.notabene.id/docs/authentication
 */
@Service
public class TokenService {

    private static final Logger log = LoggerFactory.getLogger(TokenService.class);

    private record CachedToken(String token, Instant expiresAt) {
    }

    private final NotabeneProperties properties;
    private final RestClient restClient;
    private final Map<String, CachedToken> cache = new ConcurrentHashMap<>();

    public TokenService(NotabeneProperties properties, RestClient.Builder builder) {
        this.properties = properties;
        this.restClient = builder.build();
    }

    public String accessToken(NotabeneProperties.Vasp vasp) {
        if (!vasp.hasCredentials()) {
            throw new IllegalStateException(
                    "This VASP has no clientId/clientSecret configured. Set them in application.yml or as "
                            + "environment variables. (The /api/demo endpoint needs no credentials at all.)");
        }

        CachedToken cached = cache.get(vasp.getClientId());
        if (cached != null && cached.expiresAt().isAfter(Instant.now().plusSeconds(60))) {
            return cached.token();
        }

        Map<String, String> request = new LinkedHashMap<>();
        request.put("client_id", vasp.getClientId());
        request.put("client_secret", vasp.getClientSecret());
        request.put("grant_type", "client_credentials");
        request.put("audience", properties.getAudience());

        Map<?, ?> response = restClient.post()
                .uri(properties.getAuthUrl())
                .contentType(MediaType.APPLICATION_JSON)
                .body(request)
                .retrieve()
                .body(Map.class);

        if (response == null || response.get("access_token") == null) {
            throw new NotabeneApiException("Auth returned no access_token", 500, String.valueOf(response));
        }

        String token = response.get("access_token").toString();
        long expiresIn = response.get("expires_in") instanceof Number n ? n.longValue() : 86400L;
        cache.put(vasp.getClientId(), new CachedToken(token, Instant.now().plusSeconds(expiresIn)));
        log.debug("Obtained an access token valid for {}s", expiresIn);
        return token;
    }
}
