package id.notabene.e2ee.web.dto;

import java.util.List;
import java.util.Map;

public record SendResponse(
        String transferId,
        String from,
        String to,
        String beneficiaryDid,
        /** Set when the beneficiary VASP was discovered from an address rather than named. */
        String beneficiaryDiscoveredFrom,
        String recipientKid,
        /** notabene | local | explicit - where the encryption key came from. */
        String recipientKeySource,
        String mode,
        String channel,
        int jweCount,
        List<String> encryptedPaths,
        Object encryptedIvms101,
        Map<String, Object> notabeneResponse,
        String warning) {
}
