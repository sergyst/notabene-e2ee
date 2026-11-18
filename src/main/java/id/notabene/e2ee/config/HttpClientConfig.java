package id.notabene.e2ee.config;

import java.io.InputStream;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Collection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.BufferingClientHttpRequestFactory;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

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
 * mTLS: if certs/cert.pem + certs/key.pem exist they are presented as the client
 * certificate; certs/DEV_CA.pem (if present) is trusted in addition to the JDK's
 * default CAs.
 */
@Configuration
@Slf4j
public class HttpClientConfig {

    @Bean
    public RestClient.Builder restClientBuilder(
            @Value("${notabene.tls.ca-pem:}") String caPem,
            @Value("${notabene.tls.cert-pem:}") String certPem,
            @Value("${notabene.tls.key-pem:}") String keyPem) throws Exception {

        HttpClient.Builder http = HttpClient.newBuilder();
        SSLContext ssl = sslContext(caPem, certPem, keyPem);
        if (ssl != null) {
            http.sslContext(ssl);
        }

        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(http.build());
        factory.setReadTimeout(Duration.ofSeconds(30));
        return RestClient.builder()
                .requestFactory(new BufferingClientHttpRequestFactory(factory))
                .requestInterceptor(new NotabeneHttpLogger());
    }

    private static SSLContext sslContext(String caPem, String certPem, String keyPem) throws Exception {
        boolean hasCa = exists(caPem);
        boolean hasClient = exists(certPem) && exists(keyPem);
        if (!hasCa && !hasClient) {
            log.info("No certs found ({} / {} / {}); using the JDK's default TLS", caPem, certPem, keyPem);
            return null;
        }

        KeyManager[] keyManagers = null;
        if (hasClient) {
            Certificate[] chain = readCertificates(certPem).toArray(new Certificate[0]);
            PrivateKey key = readPrivateKey(keyPem, chain[0].getPublicKey().getAlgorithm());
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setKeyEntry("client", key, new char[0], chain);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, new char[0]);
            keyManagers = kmf.getKeyManagers();
            log.info("mTLS client certificate loaded from {}", certPem);
        }

        TrustManager[] trustManagers = null;
        if (hasCa) {
            // Default JDK CAs (auth.notabene.id is public) plus DEV_CA.
            KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
            ts.load(null, null);
            TrustManagerFactory defaults = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            defaults.init((KeyStore) null);
            int i = 0;
            for (TrustManager tm : defaults.getTrustManagers()) {
                if (tm instanceof X509TrustManager x509) {
                    for (X509Certificate c : x509.getAcceptedIssuers()) {
                        ts.setCertificateEntry("default-" + i++, c);
                    }
                }
            }
            for (Certificate c : readCertificates(caPem)) {
                ts.setCertificateEntry("extra-" + i++, c);
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ts);
            trustManagers = tmf.getTrustManagers();
            log.info("Extra trusted CA loaded from {}", caPem);
        }

        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(keyManagers, trustManagers, null);
        return ssl;
    }

    private static boolean exists(String path) {
        return path != null && !path.isBlank() && Files.isReadable(Path.of(path));
    }

    private static Collection<? extends Certificate> readCertificates(String path) throws Exception {
        try (InputStream in = Files.newInputStream(Path.of(path))) {
            return CertificateFactory.getInstance("X.509").generateCertificates(in);
        }
    }

    /** Unencrypted PKCS#8 ("BEGIN PRIVATE KEY") or PKCS#1 RSA ("BEGIN RSA PRIVATE KEY"). */
    private static PrivateKey readPrivateKey(String path, String algorithm) throws Exception {
        String pem = Files.readString(Path.of(path));
        boolean pkcs1 = pem.contains("BEGIN RSA PRIVATE KEY");
        if (pem.contains("BEGIN EC PRIVATE KEY") || pem.contains("ENCRYPTED")) {
            throw new IllegalArgumentException(path + " must be an unencrypted PKCS#8 or RSA key. Convert with: "
                    + "openssl pkcs8 -topk8 -nocrypt -in key.pem -out key-pkcs8.pem");
        }
        byte[] der = Base64.getMimeDecoder().decode(
                pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", ""));
        if (pkcs1) {
            der = wrapPkcs1(der);
        }
        return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    /** Wrap a PKCS#1 RSAPrivateKey in a PKCS#8 PrivateKeyInfo envelope. */
    private static byte[] wrapPkcs1(byte[] pkcs1) {
        byte[] algId = {0x30, 0x0d, 0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01,
                0x01, 0x05, 0x00};
        byte[] version = {0x02, 0x01, 0x00};
        byte[] octet = der(0x04, pkcs1);
        byte[] body = new byte[version.length + algId.length + octet.length];
        System.arraycopy(version, 0, body, 0, version.length);
        System.arraycopy(algId, 0, body, version.length, algId.length);
        System.arraycopy(octet, 0, body, version.length + algId.length, octet.length);
        return der(0x30, body);
    }

    private static byte[] der(int tag, byte[] content) {
        int n = content.length;
        byte[] len = n < 128 ? new byte[] {(byte) n}
                : n < 256 ? new byte[] {(byte) 0x81, (byte) n}
                : new byte[] {(byte) 0x82, (byte) (n >> 8), (byte) n};
        byte[] out = new byte[1 + len.length + n];
        out[0] = (byte) tag;
        System.arraycopy(len, 0, out, 1, len.length);
        System.arraycopy(content, 0, out, 1 + len.length, n);
        return out;
    }
}
