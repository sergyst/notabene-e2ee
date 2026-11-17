package id.notabene.e2ee.web.dto;

import jakarta.validation.constraints.NotBlank;
import java.util.Map;

/**
 * Evidence that the customer controls the address, sent as the body of
 * POST /api/v1/customers/{customer}/wallets/{address}/proofs.
 *
 * Signature types (eip-191, bip-322, bip-137-xpub) carry {@code signature};
 * non-signature types (self-declaration, screenshot) carry {@code attestation}.
 * Notabene verifies signatures on submission - this server does not.
 *
 * @param type           the proof mechanism, e.g. eip-191, bip-322, bip-137-xpub, self-declaration, screenshot
 * @param attestation    the attestation text (or URL) for non-signature types; for a
 *                       signature type, the message that was signed
 * @param signature      hex- or base64-encoded signature, for signature types
 * @param walletProvider the wallet that produced the proof, e.g. MetaMask
 * @param xpub           extended public key; bip-137-xpub only
 * @param chainData      extra chain-specific fields some proof types need
 */
public record OwnershipProof(
        @NotBlank String type,
        String attestation,
        String signature,
        String walletProvider,
        String xpub,
        Map<String, Object> chainData) {
}
