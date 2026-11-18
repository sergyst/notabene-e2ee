package id.notabene.e2ee.notabene;

import id.notabene.e2ee.config.NotabeneProperties;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import id.notabene.e2ee.config.NotabeneHttpLogger;
import tools.jackson.databind.ObjectMapper;

/**
 * OAuth2 client-credentials tokens, cached per clientId until shortly before
 * they expire. https://devx.notabene.id/docs/authentication
 */
@Service
@Slf4j
public class TokenService {

    private record CachedToken(String token, Instant expiresAt) {
    }

    private final NotabeneProperties properties;
    private final WebClient webClient;
    private final ObjectMapper json;
    private final Map<String, CachedToken> cache = new ConcurrentHashMap<>();

    public TokenService(NotabeneProperties properties, WebClient.Builder builder, ObjectMapper json) {
        this.properties = properties;
        this.json = json;
        this.webClient = builder.build();
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

        String requestJson = json.writeValueAsString(request);
        Map<?, ?> response = webClient.post()
                .uri(java.net.URI.create(properties.getAuthUrl()))
                .attribute(NotabeneHttpLogger.BODY_ATTRIBUTE, requestJson)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(requestJson)
                .retrieve()
                .bodyToMono(Map.class)
                .block();

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
