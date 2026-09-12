package id.notabene.e2ee.web.dto;

import java.util.List;
import java.util.Map;

/** Everything the JavaScript demo prints, as JSON. */
public record DemoReport(
        String mode,
        String recipientKid,
        String recipientPublicKeyHex,
        Map<String, Object> plaintextPii,
        List<EncryptedPart> encryptedParts,
        Map<String, Object> jweHeader,
        Map<String, Object> wirePayload,
        String thirdPartyDecryptionError,
        Object decryptedPii,
        List<Comparison> comparison,
        boolean piiMatches,
        int mismatches,
        OtherMode otherMode) {

    public record EncryptedPart(String path, String jwePreview) {
    }

    public record Comparison(String path, Object sent, Object received, boolean match) {
    }

    public record OtherMode(String mode, boolean roundTrips, String originatorShape) {
    }
}
