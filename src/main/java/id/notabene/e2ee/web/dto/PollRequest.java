package id.notabene.e2ee.web.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * @param vasp            configured VASP name to poll for
 * @param intervalSeconds poll interval; defaults to notabene.polling.default-interval-seconds
 */
public record PollRequest(@NotBlank String vasp, Integer intervalSeconds) {
}
