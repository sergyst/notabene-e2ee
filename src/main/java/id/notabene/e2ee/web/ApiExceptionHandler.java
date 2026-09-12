package id.notabene.e2ee.web;

import id.notabene.e2ee.notabene.NotabeneApiException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Turn failures into a readable JSON body instead of a stack trace. */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(NotabeneApiException.class)
    public ResponseEntity<Map<String, Object>> notabene(NotabeneApiException e) {
        log.warn("Notabene API error: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                .body(body("notabene_api_error", e.getMessage(), e.getBody()));
    }

    @ExceptionHandler({ IllegalArgumentException.class, IllegalStateException.class })
    public ResponseEntity<Map<String, Object>> badRequest(RuntimeException e) {
        log.warn("Request rejected: {}", e.getMessage());
        return ResponseEntity.badRequest().body(body("bad_request", e.getMessage(), null));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> unexpected(Exception e) {
        log.error("Unexpected failure", e);
        return ResponseEntity.internalServerError()
                .body(body(e.getClass().getSimpleName(), e.getMessage(), null));
    }

    private static Map<String, Object> body(String error, String message, String details) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("timestamp", Instant.now().toString());
        out.put("error", error);
        out.put("message", message);
        if (details != null && !details.isBlank()) {
            out.put("details", details.substring(0, Math.min(details.length(), 2000)));
        }
        return out;
    }
}
