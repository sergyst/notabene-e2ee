package id.notabene.e2ee.web.dto;

import java.util.Map;

public record RegisterResponse(
        String vasp,
        String owner,
        String caip10,
        Map<String, Object> notabeneResponse,
        /** The status re-checked straight after registering, so you can see it took. */
        RegistrationStatus status) {
}
