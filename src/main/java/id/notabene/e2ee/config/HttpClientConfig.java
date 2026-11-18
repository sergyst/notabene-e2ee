package id.notabene.e2ee.config;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collections;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

/**
 * Spring Boot 4 does not auto-configure a RestClient.Builder, so supply one.
 *
 * Deliberately the JDK factory rather than SimpleClientHttpRequestFactory: the
 * latter is built on HttpURLConnection, which cannot issue PATCH, and
 * confirming an address relationship is a PATCH.
 *
 * The factory is buffered so the logging interceptor can read a response body
 * and still leave it readable for the caller.
 *
 * mTLS: if the PKCS#12 file (notabene.tls.keystore) exists it is presented as the
 * client identity; the JKS truststore (notabene.tls.truststore), if present, is
 * trusted in addition to the JDK's default CAs.
 */
@Configuration
@Slf4j
public class HttpClientConfig {

    @Bean
    public WebClient.Builder webClientBuilder(
            @Value("${notabene.tls.truststore:}") String truststore,
            @Value("${notabene.tls.truststore-password:changeit}") String truststorePassword,
            @Value("${notabene.tls.keystore:}") String keystore,
            @Value("${notabene.tls.keystore-password:}") String keystorePassword) throws Exception {

        HttpClient http = HttpClient.create().responseTimeout(Duration.ofSeconds(30));
        SslContext ssl = sslContext(truststore, truststorePassword, keystore, keystorePassword);
        if (ssl != null) {
            http = http.secure(spec -> spec.sslContext(ssl));
        }
        return WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(http))
                .filter(new NotabeneHttpLogger());
    }

    private static SslContext sslContext(String truststore, String truststorePassword, String keystore,
            String keystorePassword) throws Exception {
        boolean hasTrust = exists(truststore);
        boolean hasClient = exists(keystore);
        if (!hasTrust && !hasClient) {
            log.info("No certs found ({} / {}); using the JDK's default TLS", truststore, keystore);
            return null;
        }

        SslContextBuilder builder = SslContextBuilder.forClient();

        if (hasClient) {
            KeyStore p12 = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(Path.of(keystore))) {
                p12.load(in, keystorePassword.toCharArray());
            }
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(p12, keystorePassword.toCharArray());
            builder.keyManager(kmf);
            log.info("mTLS client identity loaded from {}", keystore);
        }

        if (hasTrust) {
            // Default JDK CAs (auth.notabene.id is public) plus everything in the JKS.
            KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
            ts.load(null, null);
            int i = 0;
            TrustManagerFactory defaults = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            defaults.init((KeyStore) null);
            for (TrustManager tm : defaults.getTrustManagers()) {
                if (tm instanceof X509TrustManager x509) {
                    for (X509Certificate c : x509.getAcceptedIssuers()) {
                        ts.setCertificateEntry("default-" + i++, c);
                    }
                }
            }
            KeyStore jks = KeyStore.getInstance("JKS");
            try (InputStream in = Files.newInputStream(Path.of(truststore))) {
                jks.load(in, truststorePassword.toCharArray());
            }
            for (String alias : Collections.list(jks.aliases())) {
                Certificate c = jks.getCertificate(alias);
                if (c != null) {
                    ts.setCertificateEntry("jks-" + alias, c);
                }
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ts);
            builder.trustManager(tmf);
            log.info("Extra trusted CAs loaded from {}", truststore);
        }
        return builder.build();
    }

    private static boolean exists(String path) {
        return path != null && !path.isBlank() && Files.isReadable(Path.of(path));
    }
}
