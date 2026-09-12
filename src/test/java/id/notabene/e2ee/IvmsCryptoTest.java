package id.notabene.e2ee;

import static org.assertj.core.api.Assertions.assertThat;

import id.notabene.e2ee.crypto.Jwk;
import id.notabene.e2ee.crypto.P256;
import id.notabene.e2ee.crypto.PiiCrypto;
import id.notabene.e2ee.ivms.IvmsCrypto;
import id.notabene.e2ee.ivms.PiiMode;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

class IvmsCryptoTest {

    private static final String SENDER_DID = "did:web:vasps.id:vaspa";
    private static final String RECIPIENT_KID = "did:web:vasps.id:vaspb#pii";

    private IvmsCrypto ivmsCrypto;
    private Jwk recipientPrivate;

    @BeforeEach
    void setUp() {
        ivmsCrypto = new IvmsCrypto(new PiiCrypto(new ObjectMapper()));
        KeyPair pair = P256.generateKeyPair();
        recipientPrivate = P256.toJwk((ECPublicKey) pair.getPublic(), (ECPrivateKey) pair.getPrivate());
    }

    private Map<String, Object> samplePii() {
        Map<String, Object> nameIdentifier = new LinkedHashMap<>();
        nameIdentifier.put("primaryIdentifier", "Doe");
        nameIdentifier.put("secondaryIdentifier", "John");

        Map<String, Object> address = new LinkedHashMap<>();
        address.put("addressLine", List.of("123 Main Street"));
        address.put("country", "US");

        Map<String, Object> naturalPerson = new LinkedHashMap<>();
        naturalPerson.put("name", Map.of("nameIdentifier", List.of(nameIdentifier)));
        naturalPerson.put("geographicAddress", List.of(address));

        Map<String, Object> originator = new LinkedHashMap<>();
        originator.put("originatorPerson", List.of(Map.of("naturalPerson", naturalPerson)));
        originator.put("accountNumber", "vaspA-account-0001");

        Map<String, Object> beneficiary = new LinkedHashMap<>();
        beneficiary.put("accountNumber", "vaspB-account-0002");

        Map<String, Object> ivms = new LinkedHashMap<>();
        ivms.put("originator", originator);
        ivms.put("beneficiary", beneficiary);
        return ivms;
    }

    @Test
    void branchModeProducesOneJwePerTopLevelBranch() {
        Map<String, Object> pii = samplePii();

        IvmsCrypto.EncryptResult encrypted = ivmsCrypto.encrypt(
                pii, PiiMode.BRANCH, recipientPrivate.publicOnly(), RECIPIENT_KID, SENDER_DID);

        assertThat(encrypted.parts()).hasSize(2);
        assertThat(encrypted.parts()).extracting(IvmsCrypto.Part::path)
                .containsExactly("$.originator", "$.beneficiary");

        @SuppressWarnings("unchecked")
        Map<String, Object> payload = (Map<String, Object>) encrypted.payload();
        assertThat(payload.get("originator")).isInstanceOf(String.class);
        assertThat(payload.get("beneficiary")).isInstanceOf(String.class);
        // The plaintext is nowhere in the wire payload.
        assertThat(payload.toString()).doesNotContain("Doe").doesNotContain("123 Main Street");
    }

    @Test
    void fieldModeProducesOneJwePerLeaf() {
        Map<String, Object> pii = samplePii();

        IvmsCrypto.EncryptResult encrypted = ivmsCrypto.encrypt(
                pii, PiiMode.FIELD, recipientPrivate.publicOnly(), RECIPIENT_KID, SENDER_DID);

        assertThat(encrypted.parts()).hasSize(ivmsCrypto.flattenLeaves(pii).size());

        @SuppressWarnings("unchecked")
        Map<String, Object> payload = (Map<String, Object>) encrypted.payload();
        assertThat(payload.get("originator")).isInstanceOf(Map.class);
        assertThat(payload.toString()).doesNotContain("Doe");
    }

    @Test
    void bothModesRoundTripToTheOriginalPii() {
        for (PiiMode mode : PiiMode.values()) {
            Map<String, Object> pii = samplePii();

            IvmsCrypto.EncryptResult encrypted = ivmsCrypto.encrypt(
                    pii, mode, recipientPrivate.publicOnly(), RECIPIENT_KID, SENDER_DID);
            IvmsCrypto.DecryptResult decrypted = ivmsCrypto.decrypt(
                    encrypted.payload(), recipientPrivate, SENDER_DID, RECIPIENT_KID);

            assertThat(decrypted.payload())
                    .as("%s mode must round-trip", mode.lower())
                    .isEqualTo(pii);
        }
    }

    @Test
    void decryptionAutoDetectsTheShapeItWasSent() {
        Map<String, Object> pii = samplePii();
        IvmsCrypto.EncryptResult branch = ivmsCrypto.encrypt(
                pii, PiiMode.BRANCH, recipientPrivate.publicOnly(), RECIPIENT_KID, SENDER_DID);
        IvmsCrypto.EncryptResult field = ivmsCrypto.encrypt(
                pii, PiiMode.FIELD, recipientPrivate.publicOnly(), RECIPIENT_KID, SENDER_DID);

        // Same decrypt call, no mode argument, both shapes.
        assertThat(ivmsCrypto.decrypt(branch.payload(), recipientPrivate, null, null).payload()).isEqualTo(pii);
        assertThat(ivmsCrypto.decrypt(field.payload(), recipientPrivate, null, null).payload()).isEqualTo(pii);
    }

    @Test
    void leavesPlaintextValuesAlone() {
        Map<String, Object> mixed = new LinkedHashMap<>();
        mixed.put("country", "US"); // never encrypted
        mixed.put("name", ivmsCrypto
                .encrypt(Map.of("v", "Doe"), PiiMode.FIELD, recipientPrivate.publicOnly(), RECIPIENT_KID, SENDER_DID)
                .parts().get(0).jwe());

        IvmsCrypto.DecryptResult decrypted = ivmsCrypto.decrypt(mixed, recipientPrivate, null, null);

        @SuppressWarnings("unchecked")
        Map<String, Object> payload = (Map<String, Object>) decrypted.payload();
        assertThat(payload).containsEntry("country", "US").containsEntry("name", "Doe");
        assertThat(decrypted.parts()).hasSize(1);
    }

    @Test
    void findsIvmsInsideATransferResponse() {
        Map<String, Object> pii = samplePii();
        IvmsCrypto.EncryptResult encrypted = ivmsCrypto.encrypt(
                pii, PiiMode.BRANCH, recipientPrivate.publicOnly(), RECIPIENT_KID, SENDER_DID);

        Map<String, Object> transfer = Map.of("transfer",
                Map.of("id", "abc", "status", "COMPLETED", "ivms101", encrypted.payload()));

        assertThat(ivmsCrypto.findIvms(transfer)).isEqualTo(encrypted.payload());
        assertThat(ivmsCrypto.findIvms(Map.of("transfer", Map.of("id", "abc")))).isNull();
    }

    @Test
    void flattenLeavesUsesJsonPaths() {
        assertThat(ivmsCrypto.flattenLeaves(samplePii()))
                .extracting(IvmsCrypto.Leaf::path)
                .contains("$.originator.originatorPerson[0].naturalPerson.name.nameIdentifier[0].primaryIdentifier",
                        "$.originator.originatorPerson[0].naturalPerson.geographicAddress[0].addressLine[0]",
                        "$.beneficiary.accountNumber");
    }

    @Test
    void jsonSerialisesTheValueBeforeEncrypting() {
        // Notabene's reference implementation marks this CRITICAL: the plaintext
        // for "Doe" is the five bytes "Doe" with quotes, not the bare three.
        PiiCrypto piiCrypto = new PiiCrypto(new ObjectMapper());
        String jwe = piiCrypto.encryptValue("Doe", recipientPrivate.publicOnly(), RECIPIENT_KID, SENDER_DID);

        String rawPlaintext = id.notabene.e2ee.crypto.EcdhEsJwe.decrypt(jwe, recipientPrivate, null, null);
        assertThat(rawPlaintext).isEqualTo("\"Doe\"");
        assertThat(piiCrypto.decryptValue(jwe, recipientPrivate, null, null)).isEqualTo("Doe");
    }
}
