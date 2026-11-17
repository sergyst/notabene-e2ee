package id.notabene.e2ee.service;

import id.notabene.e2ee.config.NotabeneProperties;
import id.notabene.e2ee.notabene.NotabeneClient;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * The Notabene customer each configured VASP registers wallets and transfers
 * under. v2.1 addresses everything by customer IRI (urn:uuid:...), so there has
 * to be one; it is created on first use with POST /api/v1/customers.
 */
@Service
@Slf4j
public class CustomerService {

    private final NotabeneClient client;
    private final Set<String> ensured = ConcurrentHashMap.newKeySet();

    public CustomerService(NotabeneClient client) {
        this.client = client;
    }

    /** Configured customer id, or a stable one derived from the VASP's DID. */
    public static String customerId(NotabeneProperties.Vasp vasp) {
        if (vasp.getCustomerId() != null && !vasp.getCustomerId().isBlank()) {
            return vasp.getCustomerId();
        }
        return "urn:uuid:" + UUID.nameUUIDFromBytes(("customer:" + vasp.getDid()).getBytes(StandardCharsets.UTF_8));
    }

    /** Make sure the customer exists in Notabene and return its IRI. Idempotent. */
    public String ensure(NotabeneProperties.Vasp vasp) {
        String id = customerId(vasp);
        if (ensured.contains(id)) {
            return id;
        }
        Map<String, Object> name = Map.of(
                "primaryIdentifier", "Doe",
                "secondaryIdentifier", "John",
                "naturalPersonNameIdentifierType", "LEGL");
        Map<String, Object> body = Map.of(
                "id", id,
                "type", "Individual",
                "profile", Map.of("ivms", Map.of("naturalPerson",
                        Map.of("name", Map.of("nameIdentifier", List.of(name))))));
        client.ensureCustomer(vasp, body);
        ensured.add(id);
        log.info("customer {} is registered for {}", id, vasp.getDid());
        return id;
    }
}
