package id.notabene.e2ee.web.dto;

import jakarta.validation.constraints.NotBlank;
import java.util.Map;

/**
 * A signature proving control of the address being registered.
 *
 * Without one a registration would only be a self-declaration ("the claimant
 * says so"), so POST /api/register/complete requires it and Notabene verifies it.
 * Notabene documents PROVEN as the relationship status for a signature proof;
 * how lookup reports it is unverified against a live call.
 *
 * This server does NOT verify the signature - Notabene does. Sign the exact
 * string returned by GET /api/register/initiate, because the attestation
 * carries a timestamp and the bytes must match what you signed.
 *
 * @param type        signature scheme; defaults to eip-191. Notabene also accepts
 *                    eip-712, eip-1271, bip-137, bip-322, tip-191, ed25519,
 *                    xrp-ed25519, xlm-ed25519, cip-8, siwe, siwx
 * @param attestation the exact message that was signed
 * @param signature   the signature over it
 * @param status      pending, rejected, flagged or verified; defaults to verified
 * @param xpub        optional extended public key, for schemes that use one
 * @param chainSpecificData optional extra fields some schemes require
 */
public record OwnershipProof(
        String type,
        @NotBlank String attestation,
        @NotBlank String signature,
        String status,
        String xpub,
        Map<String, Object> chainSpecificData) {
}
