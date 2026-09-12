package id.notabene.e2ee.vasp;

import id.notabene.e2ee.crypto.Jwk;
import java.util.Map;

/**
 * A VASP's PII keypair. Mirrors the JSON the JavaScript project writes to
 * keys/*.json field for field, so the two projects can share key files.
 */
public record VaspKeypair(
        String name,
        String did,
        String kid,
        String privateKeyHex,
        String publicKeyHex,
        String publicKeyHexUncompressed,
        Jwk privateJwk,
        Jwk publicJwk,
        /** JsonWebKey2020 + publicKeyJwk, the form Notabene's current V2 recipe uses. */
        Map<String, Object> didDocEntry,
        /** EcdsaSecp256r1VerificationKey2019 + publicKeyHex, the form their DIDDoc guide uses. */
        Map<String, Object> didDocEntryHexVariant) {
}
