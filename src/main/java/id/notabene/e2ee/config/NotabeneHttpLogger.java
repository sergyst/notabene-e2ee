package id.notabene.e2ee.config;

import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import reactor.core.publisher.Mono;

/**
 * Logs every outbound call - Notabene's API and its OAuth endpoint - with the
 * request, the response, the status and how long it took.
 *
 * Separate logger name so it can be switched on its own:
 * {@code logging.level.notabene.http=DEBUG}. The Authorization header is never
 * logged, and secrets/tokens in JSON bodies are masked. The PII in a
 * presentation is JWE ciphertext by the time it gets here, so it is safe to log.
 *
 * WebClient streams request bodies, so callers pass the serialized body as the
 * {@link #BODY_ATTRIBUTE} request attribute for it to be logged.
 */
@Slf4j(topic = "notabene.http")
public class NotabeneHttpLogger implements ExchangeFilterFunction {

    public static final String BODY_ATTRIBUTE = "notabene.http.body";

    private static final int MAX_BODY = 10_000;
    private static final Pattern SECRET = Pattern.compile(
            "(\"(?:client_secret|access_token|refresh_token|id_token)\"\\s*:\\s*\")[^\"]*(\")");

    @Override
    public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
        if (!log.isDebugEnabled()) {
            return next.exchange(request);
        }
        Object requestBody = request.attribute(BODY_ATTRIBUTE).orElse(null);
        long[] started = new long[1];
        return Mono.defer(() -> {
            started[0] = System.nanoTime();
            log.debug("--> {} {}{}", request.method(), request.url(),
                    describe(requestBody == null ? null : requestBody.toString()));
            return next.exchange(request);
        }).flatMap(response -> response.bodyToMono(byte[].class).defaultIfEmpty(new byte[0]).map(bytes -> {
            String text = new String(bytes, StandardCharsets.UTF_8);
            log.debug("<-- {} {} {} ({} ms){}", response.statusCode().value(), request.method(), request.url(),
                    elapsedMs(started[0]), describe(text));
            // The body was consumed above; give the caller an equivalent response.
            return ClientResponse.create(response.statusCode(), ExchangeStrategies.withDefaults())
                    .headers(h -> {
                        h.addAll(response.headers().asHttpHeaders());
                        h.remove(HttpHeaders.CONTENT_LENGTH);
                        h.remove(HttpHeaders.CONTENT_ENCODING);
                    })
                    .body(text)
                    .build();
        })).doOnError(e -> log.debug("<-- FAILED {} {} after {} ms: {}", request.method(), request.url(),
                elapsedMs(started[0]), e.toString()));
    }

    private static long elapsedMs(long startedNanos) {
        return (System.nanoTime() - startedNanos) / 1_000_000;
    }

    private static String describe(String body) {
        if (body == null || body.isEmpty()) {
            return " [no body]";
        }
        String text = SECRET.matcher(body).replaceAll("$1***$2");
        if (text.length() > MAX_BODY) {
            text = text.substring(0, MAX_BODY) + "… [" + (text.length() - MAX_BODY) + " more chars]";
        }
        return "\n" + text;
    }
}
