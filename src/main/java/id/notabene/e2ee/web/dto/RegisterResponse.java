package id.notabene.e2ee.web.dto;

import java.util.Map;

/**
 * @param customerId the Notabene customer IRI the wallet was registered under
 * @param wallet     Notabene's answer to POST /api/v1/wallets
 * @param proof      Notabene's answer to the proof submission (id, type, status Submitted | Accepted | Failed)
 * @param status     ownership lookup re-run straight after registering
 */
public record RegisterResponse(
        String vasp,
        String customerId,
        String caip10,
        Map<String, Object> wallet,
        Map<String, Object> proof,
        RegistrationStatus status) {
}
