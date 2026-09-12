package id.notabene.e2ee.web.dto;

import java.time.Instant;
import java.util.List;

public record PollStatus(
        String vasp,
        boolean running,
        int intervalSeconds,
        Instant startedAt,
        int polls,
        int decryptedMessages,
        String lastError,
        List<ReceivedMessage> recent,
        String message) {
}
