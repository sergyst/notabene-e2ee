package id.notabene.e2ee.web.dto;

import java.util.Map;

/**
 * Who owns a blockchain address, as far as Notabene can tell.
 *
 * Discovery draws on three sources: relationships you and your counterparties
 * have registered, the Hashed Address Service, and blockchain analytics.
 *
 * @param confidence CONFIRMED, UNCONFIRMED or NOT_FOUND
 * @param owned      true when an owning agent was found at all
 */
public record AddressOwnership(
        String address,
        String asset,
        String confidence,
        boolean owned,
        String agentDid,
        String agentName,
        String agentJurisdiction,
        String custodianDid,
        String custodianName,
        String checkedAs,
        Map<String, Object> raw) {
}
