package id.notabene.e2ee;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.sun.net.httpserver.HttpServer;
import id.notabene.e2ee.config.HttpClientConfig;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;

/** Every Notabene call is logged, secrets are masked, and the caller still gets the body. */
class NotabeneHttpLoggerTest {

    private HttpServer server;
    private ListAppender<ILoggingEvent> logs;
    private Logger logger;
    private Level previousLevel;

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/echo", exchange -> {
            byte[] reply = "{\"access_token\":\"SECRET-TOKEN\",\"ok\":true}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, reply.length);
            exchange.getResponseBody().write(reply);
            exchange.close();
        });
        server.start();

        logger = (Logger) LoggerFactory.getLogger("notabene.http");
        previousLevel = logger.getLevel();
        logger.setLevel(Level.DEBUG);
        logs = new ListAppender<>();
        logs.start();
        logger.addAppender(logs);
    }

    @AfterEach
    void stop() {
        server.stop(0);
        logger.detachAppender(logs);
        logger.setLevel(previousLevel);
    }

    @Test
    void logsRequestAndResponse_masksSecrets_andLeavesTheBodyReadable() {
        RestClient client = new HttpClientConfig().restClientBuilder().build();

        Map<String, Object> body = client.post()
                .uri("http://127.0.0.1:" + server.getAddress().getPort() + "/echo")
                .header("Authorization", "Bearer BEARER-VALUE")
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("client_secret", "TOP-SECRET", "asset", "eip155:1"))
                .retrieve()
                .body(new ParameterizedTypeReference<Map<String, Object>>() {});

        assertThat(body).containsEntry("ok", true);

        String all = String.join("\n", logs.list.stream().map(ILoggingEvent::getFormattedMessage).toList());
        assertThat(all).contains("--> POST", "/echo", "eip155:1", "<-- 200", "\"ok\":true");
        assertThat(all).doesNotContain("TOP-SECRET", "SECRET-TOKEN", "BEARER-VALUE");
        assertThat(all).contains("\"client_secret\":\"***\"", "\"access_token\":\"***\"");
    }
}
