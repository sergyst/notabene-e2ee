package id.notabene.e2ee.web.dto;

import java.util.List;
import java.util.Map;

/**
 * A single transfer with both sides of the encryption shown: what the platform
 * holds, and what this VASP can read from it.
 */
public record TransferDetail(
        TransferSummary summary,
        boolean hasPii,
        /** The IVMS101 exactly as stored - every value an opaque JWE. */
        Object encryptedIvms101,
        /** Decrypted with this VASP's own private key, or null if it could not be. */
        Object decryptedPii,
        String decryptError,
        int jweCount,
        /** The protected header of the first JWE, so the UI can show alg/enc/kid/apu/apv. */
        Map<String, Object> jweHeader,
        List<FieldValue> fields) {

    public record FieldValue(String path, Object value) {
    }
}
