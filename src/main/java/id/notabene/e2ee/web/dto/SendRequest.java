package id.notabene.e2ee.web.dto;

import jakarta.validation.constraints.NotBlank;
import java.util.Map;

/**
 * @param from         configured VASP name that originates (e.g. "vaspA")
 * @param beneficiaryAddress settlement address; Notabene is asked who owns it and that VASP
 *                     becomes the beneficiary. Bare ("0x…") or already CAIP-10.
 * @param network      chain of that address: a friendly name ("ethereum") or a CAIP-2 id
 *                     ("eip155:1"). An address naming a different chain is rejected.
 * @param asset        CAIP-19 override for address-ownership discovery; derived from the network
 * @param mode         branch or field; defaults to notabene.pii-mode
 * @param channel      notabene (default) or local, an in-memory stand-in
 * @param transferId   present PII on an existing transfer instead of creating one
 * @param policyId     fulfil one specific policy instead of every open one
 * @param pii          IVMS101 payload; defaults to sample-pii.json
 * @param recipientKey which public key to encrypt to; omit to ask Notabene
 */
public record SendRequest(
        @NotBlank String from,
        @NotBlank String beneficiaryAddress,
        @NotBlank String network,
        String asset,
        String mode,
        String channel,
        String transferId,
        String policyId,
        String originatorId,
        String beneficiaryId,
        Map<String, Object> pii,
        RecipientKey recipientKey) {
}
