package id.notabene.e2ee.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

/**
 * Logs every outbound call - Notabene's API and its OAuth endpoint - with the
 * request, the response, the status and how long it took.
 *
 * Separate logger name so it can be switched on its own:
 * {@code logging.level.notabene.http=DEBUG}. The Authorization header is never
 * logged, and secrets/tokens in JSON bodies are masked. The PII in a
 * presentation is JWE ciphertext by the time it gets here, so it is safe to log.
 */
@Slf4j(topic = "notabene.http")
public class NotabeneHttpLogger implements ClientHttpRequestInterceptor {

    private static final int MAX_BODY = 10_000;
    private static final Pattern SECRET = Pattern.compile(
            "(\"(?:client_secret|access_token|refresh_token|id_token)\"\\s*:\\s*\")[^\"]*(\")");

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        if (!log.isDebugEnabled()) {
            return execution.execute(request, body);
        }

        log.debug("--> {} {}{}", request.getMethod(), request.getURI(), describe(body));
        long started = System.nanoTime();
        try {
            ClientHttpResponse response = execution.execute(request, body);
            byte[] responseBody = response.getBody().readAllBytes();
            log.debug("<-- {} {} {} ({} ms){}", response.getStatusCode().value(), request.getMethod(),
                    request.getURI(), elapsedMs(started), describe(responseBody));
            return response;
        } catch (IOException e) {
            log.debug("<-- FAILED {} {} after {} ms: {}", request.getMethod(), request.getURI(),
                    elapsedMs(started), e.toString());
            throw e;
        }
    }

    private static long elapsedMs(long startedNanos) {
        return (System.nanoTime() - startedNanos) / 1_000_000;
    }

    private static String describe(byte[] body) {
        if (body == null || body.length == 0) {
            return " [no body]";
        }
        String text = SECRET.matcher(new String(body, StandardCharsets.UTF_8)).replaceAll("$1***$2");
        if (text.length() > MAX_BODY) {
            text = text.substring(0, MAX_BODY) + "… [" + (text.length() - MAX_BODY) + " more chars]";
        }
        return "\n" + text;
    }
}
