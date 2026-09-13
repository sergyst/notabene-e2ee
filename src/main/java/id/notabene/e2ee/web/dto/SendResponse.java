package id.notabene.e2ee.web.dto;

import java.util.List;
import java.util.Map;

public record SendResponse(
        String transferId,
        String from,
        String to,
        String recipientKid,
        String mode,
        String channel,
        int jweCount,
        List<String> encryptedPaths,
        Object encryptedIvms101,
        Map<String, Object> notabeneResponse,
        String warning) {
}
