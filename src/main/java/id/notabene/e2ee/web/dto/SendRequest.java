package id.notabene.e2ee.web.dto;

import jakarta.validation.constraints.NotBlank;
import java.util.Map;

/**
 * @param from         configured VASP name that originates (e.g. "vaspA")
 * @param to           configured VASP name that receives (e.g. "vaspB")
 * @param mode         branch or field; defaults to notabene.pii-mode
 * @param channel      notabene (default) or local, an in-memory stand-in
 * @param transferId   present PII on an existing transfer instead of creating one
 * @param policyId     fulfil one specific policy instead of every open one
 * @param pii          IVMS101 payload; defaults to sample-pii.json
 */
public record SendRequest(
        @NotBlank String from,
        @NotBlank String to,
        String mode,
        String channel,
        String transferId,
        String policyId,
        String originatorId,
        String beneficiaryId,
        Map<String, Object> pii) {
}
