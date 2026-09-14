package id.notabene.e2ee.config;

import java.time.Duration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

/**
 * Spring Boot 4 does not auto-configure a RestClient.Builder, so supply one.
 *
 * Deliberately the JDK factory rather than SimpleClientHttpRequestFactory: the
 * latter is built on HttpURLConnection, which cannot issue PATCH, and
 * confirming an address relationship is a PATCH.
 */
@Configuration
public class HttpClientConfig {

    @Bean
    public RestClient.Builder restClientBuilder() {
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory();
        factory.setReadTimeout(Duration.ofSeconds(30));
        return RestClient.builder().requestFactory(factory);
    }
}
