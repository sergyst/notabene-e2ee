package id.notabene.e2ee.web.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * Register a blockchain address to one of the configured VASPs, so counterparties
 * discover that VASP as its owner. A signed proof of control is mandatory; the
 * registration is always made to the VASP's own DID.
 *
 * @param vasp    configured VASP name the address belongs to
 * @param address the address; bare ("0x…") or already CAIP-10 for this network
 * @param network friendly name ("ethereum", "sepolia") or a CAIP-2 id ("eip155:1")
 * @param asset   optional CAIP-19 override for the ownership lookup
 * @param proof   signature over the message from GET /api/register/initiate
 */
public record RegisterRequest(
        @NotBlank String vasp,
        @NotBlank String address,
        @NotBlank String network,
        String asset,
        @NotNull @Valid OwnershipProof proof) {
}
