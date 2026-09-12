package id.notabene.e2ee.crypto;

import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

/**
 * Encrypt and decrypt PII values the way Notabene expects.
 *
 * Their reference implementation is explicit about this: the value is
 * JSON-serialised before encryption ("CRITICAL: JSON.stringify the value for
 * Notabene compatibility" in EcdhEsUtils.encryptPiiValue). So the plaintext for
 * "Doe" is the five bytes "Doe" with the quotes, not the bare three.
 *
 * Because the payload is JSON, the value can just as well be a whole Map, which
 * is how a complete ivms101.originator branch gets encrypted in one go.
 */
@Component
public class PiiCrypto {

    private final ObjectMapper json;

    public PiiCrypto(ObjectMapper json) {
        this.json = json;
    }

    public String encryptValue(Object value, Jwk recipientJwk, String recipientKid, String senderDid) {
        return EcdhEsJwe.encrypt(json.writeValueAsString(value), recipientJwk, recipientKid, senderDid);
    }

    /** Inverse of {@link #encryptValue}: returns the original value, not a string. */
    public Object decryptValue(String jwe, Jwk privateJwk, String expectedSenderDid, String expectedRecipientKid) {
        String plaintext = EcdhEsJwe.decrypt(jwe, privateJwk, expectedSenderDid, expectedRecipientKid);
        return json.readValue(plaintext, Object.class);
    }
}
