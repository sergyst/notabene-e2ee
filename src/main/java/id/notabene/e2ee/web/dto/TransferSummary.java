package id.notabene.e2ee.web.dto;

import java.util.Map;

/** One row in the client's transfer table. */
public record TransferSummary(
        String id,
        String vasp,
        String vaspDid,
        String channel,
        String direction,
        String status,
        String asset,
        String amount,
        String createdAt,
        String originator,
        String beneficiary,
        String counterparty,
        String ref,
        Map<String, Object> raw) {
}
