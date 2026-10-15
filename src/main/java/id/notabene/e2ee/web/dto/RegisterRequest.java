package id.notabene.e2ee.web.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Register a blockchain address to one of the configured VASPs, so counterparties
 * discover that VASP as its owner.
 *
 * @param vasp    configured VASP name the address belongs to
 * @param address the address; bare ("0x…") or already CAIP-10 for this network
 * @param network friendly name ("ethereum", "sepolia") or a CAIP-2 id ("eip155:1")
 * @param asset   optional CAIP-19 override for the ownership lookup
 * @param owner   optional DID to register against; defaults to the VASP's own DID
 */
public record RegisterRequest(
        @NotBlank String vasp,
        @NotBlank String address,
        @NotBlank String network,
        String asset,
        String owner) {
}
