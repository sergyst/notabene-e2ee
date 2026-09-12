package id.notabene.e2ee;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import id.notabene.e2ee.crypto.Base64Url;
import id.notabene.e2ee.crypto.ConcatKdf;
import id.notabene.e2ee.crypto.EcdhEsJwe;
import id.notabene.e2ee.crypto.Hex;
import id.notabene.e2ee.crypto.Jwk;
import id.notabene.e2ee.crypto.P256;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Map;
import org.junit.jupiter.api.Test;

class EcdhEsJweTest {

    private static final String SENDER_DID = "did:web:vasps.id:vaspa";
    private static final String RECIPIENT_KID = "did:web:vasps.id:vaspb#pii";

    private Jwk recipientPrivate() {
        KeyPair pair = P256.generateKeyPair();
        return P256.toJwk((ECPublicKey) pair.getPublic(), (ECPrivateKey) pair.getPrivate());
    }

    @Test
    void roundTripsAValue() {
        Jwk priv = recipientPrivate();
        String jwe = EcdhEsJwe.encrypt("\"Doe\"", priv.publicOnly(), RECIPIENT_KID, SENDER_DID);

        assertThat(jwe.split("\\.", -1)).hasSize(5);
        assertThat(jwe.split("\\.", -1)[1]).isEmpty(); // direct ECDH-ES

        assertThat(EcdhEsJwe.decrypt(jwe, priv, SENDER_DID, RECIPIENT_KID)).isEqualTo("\"Doe\"");
    }

    @Test
    void producesTheHeaderNotabeneDocuments() {
        Jwk priv = recipientPrivate();
        String jwe = EcdhEsJwe.encrypt("\"Doe\"", priv.publicOnly(), RECIPIENT_KID, SENDER_DID);
        Map<String, Object> header = EcdhEsJwe.readHeader(jwe);

        assertThat(header).containsEntry("alg", "ECDH-ES").containsEntry("enc", "A256GCM")
                .containsEntry("typ", "JWE").containsEntry("kid", RECIPIENT_KID);
        assertThat(header.get("apu")).isEqualTo(Base64Url.encode(ConcatKdf.sha256(SENDER_DID)));
        assertThat(header.get("apv")).isEqualTo(Base64Url.encode(ConcatKdf.sha256(RECIPIENT_KID)));

        @SuppressWarnings("unchecked")
        Map<String, Object> epk = (Map<String, Object>) header.get("epk");
        assertThat(epk).containsEntry("kty", "EC").containsEntry("crv", "P-256").containsKeys("x", "y");
    }

    @Test
    void usesAFreshEphemeralKeyEveryTime() {
        Jwk priv = recipientPrivate();
        String first = EcdhEsJwe.encrypt("\"Doe\"", priv.publicOnly(), RECIPIENT_KID, SENDER_DID);
        String second = EcdhEsJwe.encrypt("\"Doe\"", priv.publicOnly(), RECIPIENT_KID, SENDER_DID);

        assertThat(EcdhEsJwe.readHeader(first).get("epk"))
                .isNotEqualTo(EcdhEsJwe.readHeader(second).get("epk"));
        assertThat(first).isNotEqualTo(second);
    }

    @Test
    void aThirdPartyKeyCannotDecrypt() {
        Jwk recipient = recipientPrivate();
        Jwk eavesdropper = recipientPrivate();
        String jwe = EcdhEsJwe.encrypt("\"Doe\"", recipient.publicOnly(), RECIPIENT_KID, SENDER_DID);

        assertThatThrownBy(() -> EcdhEsJwe.decrypt(jwe, eavesdropper, null, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("AES-GCM authentication failed");
    }

    @Test
    void rejectsAWrongSenderBinding() {
        Jwk priv = recipientPrivate();
        String jwe = EcdhEsJwe.encrypt("\"Doe\"", priv.publicOnly(), RECIPIENT_KID, SENDER_DID);

        assertThatThrownBy(() -> EcdhEsJwe.decrypt(jwe, priv, "did:web:vasps.id:someone-else", RECIPIENT_KID))
                .hasMessageContaining("APU mismatch");
        assertThatThrownBy(() -> EcdhEsJwe.decrypt(jwe, priv, SENDER_DID, "did:web:vasps.id:vaspb#other"))
                .hasMessageContaining("APV mismatch");
    }

    @Test
    void detectsTamperedCiphertext() {
        Jwk priv = recipientPrivate();
        String jwe = EcdhEsJwe.encrypt("\"Doe\"", priv.publicOnly(), RECIPIENT_KID, SENDER_DID);
        String[] parts = jwe.split("\\.", -1);
        byte[] ciphertext = Base64Url.decode(parts[3]);
        ciphertext[0] ^= 0x01;
        String tampered = parts[0] + ".." + parts[2] + "." + Base64Url.encode(ciphertext) + "." + parts[4];

        assertThatThrownBy(() -> EcdhEsJwe.decrypt(tampered, priv, null, null))
                .hasMessageContaining("AES-GCM authentication failed");
    }

    @Test
    void recognisesOurOwnJwes() {
        Jwk priv = recipientPrivate();
        assertThat(EcdhEsJwe.looksLikeJwe(EcdhEsJwe.encrypt("\"x\"", priv.publicOnly(), RECIPIENT_KID, SENDER_DID)))
                .isTrue();
        assertThat(EcdhEsJwe.looksLikeJwe("Doe")).isFalse();
        assertThat(EcdhEsJwe.looksLikeJwe("a.b.c.d.e")).isFalse();
        assertThat(EcdhEsJwe.looksLikeJwe(42)).isFalse();
        assertThat(EcdhEsJwe.looksLikeJwe(null)).isFalse();
    }

    @Test
    void compressedAndUncompressedPointsAgree() {
        KeyPair pair = P256.generateKeyPair();
        ECPublicKey publicKey = (ECPublicKey) pair.getPublic();

        Jwk fromCompressed = P256.hexToJwk(Hex.encode(P256.encodePoint(publicKey, true)));
        Jwk fromUncompressed = P256.hexToJwk(Hex.encode(P256.encodePoint(publicKey, false)));

        assertThat(fromCompressed).isEqualTo(fromUncompressed).isEqualTo(P256.toJwk(publicKey));
    }

    @Test
    void rejectsAnOffCurveEphemeralKey() {
        Jwk priv = recipientPrivate();
        String jwe = EcdhEsJwe.encrypt("\"Doe\"", priv.publicOnly(), RECIPIENT_KID, SENDER_DID);
        Map<String, Object> header = EcdhEsJwe.readHeader(jwe);

        @SuppressWarnings("unchecked")
        Map<String, Object> epk = (Map<String, Object>) header.get("epk");
        byte[] y = Base64Url.decode(epk.get("y").toString());
        y[31] ^= 0x01; // no longer a point on P-256
        epk.put("y", Base64Url.encode(y));

        String forged = Base64Url.encode(new tools.jackson.databind.ObjectMapper().writeValueAsString(header))
                + ".." + String.join(".", jwe.split("\\.", -1)[2], jwe.split("\\.", -1)[3], jwe.split("\\.", -1)[4]);

        assertThatThrownBy(() -> EcdhEsJwe.decrypt(forged, priv, null, null))
                .hasMessageContaining("not on the P-256 curve");
    }
}
