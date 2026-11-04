package id.notabene.e2ee.web;

import id.notabene.e2ee.notabene.NotabeneApiException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Turn failures into a readable JSON body instead of a stack trace. */
@RestControllerAdvice
@Slf4j
public class ApiExceptionHandler {

    @ExceptionHandler(NotabeneApiException.class)
    public ResponseEntity<Map<String, Object>> notabene(NotabeneApiException e) {
        log.warn("Notabene API error: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                .body(body("notabene_api_error", e.getMessage(), e.getBody()));
    }

    @ExceptionHandler(org.springframework.web.bind.MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> invalidBody(
            org.springframework.web.bind.MethodArgumentNotValidException e) {
        String fields = e.getBindingResult().getFieldErrors().stream()
                .map(f -> f.getField() + " " + f.getDefaultMessage())
                .reduce((a, b) -> a + "; " + b)
                .orElse("request body is invalid");
        log.warn("Request rejected: {}", fields);
        return ResponseEntity.badRequest().body(body("bad_request", fields, null));
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
