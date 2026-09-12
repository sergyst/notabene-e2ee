package id.notabene.e2ee;

import static org.assertj.core.api.Assertions.assertThat;

import id.notabene.e2ee.crypto.EcdhEsJwe;
import id.notabene.e2ee.crypto.Jwk;
import id.notabene.e2ee.crypto.P256;
import id.notabene.e2ee.crypto.PiiCrypto;
import id.notabene.e2ee.ivms.IvmsCrypto;
import id.notabene.e2ee.ivms.PiiMode;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

/**
 * Cross-language interoperability against the JavaScript project
 * (notabene-e2ee-js).
 *
 * javascript-interop-vector.json was produced by that project's own
 * encryptIVMS/encryptPiiValue. If this Java implementation ever drifts from it
 * - a different ConcatKDF input, a missing JSON.stringify, the wrong AAD -
 * these tests fail. No Node needed to run them.
 */
class JavaScriptInteropTest {

    private ObjectMapper json;
    private IvmsCrypto ivmsCrypto;
    private PiiCrypto piiCrypto;
    private Map<String, Object> vector;
    private Jwk privateJwk;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() throws Exception {
        json = new ObjectMapper();
        piiCrypto = new PiiCrypto(json);
        ivmsCrypto = new IvmsCrypto(piiCrypto);
        try (InputStream in = getClass().getResourceAsStream("/javascript-interop-vector.json")) {
            vector = json.readValue(new String(in.readAllBytes(), StandardCharsets.UTF_8), Map.class);
        }
        privateJwk = Jwk.fromMap((Map<String, ?>) vector.get("privateJwk"));
    }

    private String kid() {
        return vector.get("kid").toString();
    }

    private String senderDid() {
        return vector.get("senderDid").toString();
    }

    @Test
    void javaDecryptsASingleValueEncryptedByJavaScript() {
        Object value = piiCrypto.decryptValue(
                vector.get("singleValueJwe").toString(), privateJwk, senderDid(), kid());

        assertThat(value).isEqualTo("Doe");
    }

    @Test
    void javaDecryptsAWholeBranchEncryptedByJavaScript() {
        @SuppressWarnings("unchecked")
        Map<String, Object> expectedPii = (Map<String, Object>) vector.get("pii");

        Map<String, Object> wirePayload = Map.of(
                "originator", vector.get("branchJwe"),
                "beneficiary", vector.get("beneficiaryJwe"));

        IvmsCrypto.DecryptResult decrypted = ivmsCrypto.decrypt(wirePayload, privateJwk, senderDid(), kid());

        assertThat(decrypted.parts()).hasSize(2);
        assertThat(decrypted.payload()).isEqualTo(expectedPii);
    }

    @Test
    void theJavaScriptPublicKeyHexDecodesToTheSameJwk() {
        Jwk fromHex = P256.hexToJwk(vector.get("publicKeyHex").toString());

        assertThat(fromHex).isEqualTo(privateJwk.publicOnly());
    }

    @Test
    void javaScriptBindingsSurviveVerification() {
        // apu/apv were computed by the JavaScript side; ours must agree, or the
        // unknown-key-share checks would reject a legitimate message.
        Map<String, Object> header = EcdhEsJwe.readHeader(vector.get("singleValueJwe").toString());

        assertThat(header).containsEntry("alg", "ECDH-ES").containsEntry("enc", "A256GCM")
                .containsEntry("kid", kid());
        assertThat(header.get("apu")).isNotNull();
        assertThat(header.get("apv")).isNotNull();
    }

    @Test
    void javaReEncryptsToTheSameKeyAndStillRoundTrips() {
        // The other direction is verified by re-encrypting to the JavaScript
        // key and decrypting here; the wire format is symmetric.
        @SuppressWarnings("unchecked")
        Map<String, Object> pii = (Map<String, Object>) vector.get("pii");

        IvmsCrypto.EncryptResult encrypted = ivmsCrypto.encrypt(
                pii, PiiMode.BRANCH, privateJwk.publicOnly(), kid(), senderDid());

        assertThat(ivmsCrypto.decrypt(encrypted.payload(), privateJwk, senderDid(), kid()).payload())
                .isEqualTo(pii);
    }
}
