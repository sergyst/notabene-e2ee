package id.notabene.e2ee.web.dto;

/**
 * The exact message to sign with the address's private key, plus the context it
 * commits to. Sign {@code message} verbatim - it carries a timestamp, so
 * rebuilding it later will produce different bytes.
 */
public record Attestation(
        String message,
        String caip10,
        String owner,
        String network,
        String suggestedType,
        String howToSign) {
}
