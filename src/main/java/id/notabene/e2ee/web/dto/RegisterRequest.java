package id.notabene.e2ee.web.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * Register a blockchain address under one of the configured VASPs' Notabene
 * customer and submit proof that the customer controls it.
 *
 * @param vasp    configured VASP name the address belongs to
 * @param address the address; bare ("0x…") or already CAIP-10 for this network
 * @param network friendly name ("ethereum", "sepolia") or a CAIP-2 id ("eip155:1")
 * @param managed false (the default) registers a self-hosted wallet, which is what
 *                a proof of ownership is for; true registers a hosted wallet
 * @param proof   the ownership proof
 */
public record RegisterRequest(
        @NotBlank String vasp,
        @NotBlank String address,
        @NotBlank String network,
        Boolean managed,
        @NotNull @Valid OwnershipProof proof) {
}
