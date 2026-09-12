package id.notabene.e2ee.web.dto;

import java.time.Instant;

public record ReceivedMessage(
        String transferId,
        Instant decryptedAt,
        String transferStatus,
        int jweCount,
        Object pii) {
}
