package id.notabene.e2ee.web.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Claim a blockchain address for an entity, so counterparties can discover who
 * owns it. Upserts, then confirms.
 *
 * @param vasp    configured VASP name making the claim
 * @param address the address, as "0x…", "eip155:1:0x…" or "did:pkh:eip155:1:0x…"
 * @param owner   DID that owns it; defaults to the calling VASP's own DID
 * @param asset   for the follow-up ownership check; defaults to notabene.transfer.asset
 */
public record AddOwnershipRequest(
        @NotBlank String vasp,
        @NotBlank String address,
        String owner,
        String asset) {
}
