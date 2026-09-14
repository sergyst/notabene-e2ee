package id.notabene.e2ee.web.dto;

import java.util.Map;

public record AddOwnershipResponse(
        String vasp,
        String address,
        String owner,
        Map<String, Object> notabeneResponse,
        /** The ownership check re-run straight after the claim. */
        AddressOwnership ownership) {
}
