package id.notabene.e2ee.service;

import id.notabene.e2ee.config.NotabeneProperties;
import id.notabene.e2ee.notabene.Addresses;
import id.notabene.e2ee.notabene.NotabeneClient;
import id.notabene.e2ee.web.dto.AddOwnershipRequest;
import id.notabene.e2ee.web.dto.AddOwnershipResponse;
import id.notabene.e2ee.web.dto.AddressOwnership;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Who owns a blockchain address, and claiming one for yourself.
 *
 * This matters more than it looks: Notabene's receiving guide says a
 * counterparty will usually only send Travel Rule PII once you have confirmed
 * that the destination address is yours. An address nobody has claimed is an
 * address nobody will send PII about.
 */
@Service
public class AddressOwnershipService {

    private static final Logger log = LoggerFactory.getLogger(AddressOwnershipService.class);

    private final NotabeneProperties properties;
    private final NotabeneClient client;

    public AddressOwnershipService(NotabeneProperties properties, NotabeneClient client) {
        this.properties = properties;
        this.client = client;
    }

    /** Does this address have a known owner? */
    public AddressOwnership check(String vaspName, String address, String asset) {
        NotabeneProperties.Vasp caller = properties.requireVasp(vaspName);
        String resolvedAsset = (asset == null || asset.isBlank()) ? properties.getTransfer().getAsset() : asset;
        String query = Addresses.toCaip10(address);

        Map<String, Object> response = client.discoverAddressOwnership(caller, resolvedAsset, query);
        AddressOwnership ownership = toOwnership(response, query, resolvedAsset, vaspName);
        log.info("{}: {} -> {} ({})", vaspName, query,
                ownership.agentDid() == null ? "no owner found" : ownership.agentDid(), ownership.confidence());
        return ownership;
    }

    /** Claim the address for an entity, then re-check so you can see it took. */
    public AddOwnershipResponse claim(AddOwnershipRequest request) {
        NotabeneProperties.Vasp caller = properties.requireVasp(request.vasp());
        String owner = (request.owner() == null || request.owner().isBlank())
                ? caller.getDid()
                : request.owner();
        String from = Addresses.toDidPkh(request.address());

        Map<String, Object> response = client.confirmRelationship(caller, from, owner);
        log.info("{}: claimed {} for {}", request.vasp(), from, owner);

        return new AddOwnershipResponse(request.vasp(), from, owner, response,
                check(request.vasp(), request.address(), request.asset()));
    }

    @SuppressWarnings("unchecked")
    private static AddressOwnership toOwnership(Map<String, Object> response, String address, String asset,
            String checkedAs) {
        Map<String, Object> body = response.get("addressOwnership") instanceof Map<?, ?> m
                ? (Map<String, Object>) m
                : response;
        Map<String, Object> agent = body.get("agent") instanceof Map<?, ?> a ? (Map<String, Object>) a : Map.of();
        Map<String, Object> custodian = body.get("custodian") instanceof Map<?, ?> c
                ? (Map<String, Object>) c
                : Map.of();

        String confidence = str(body.getOrDefault("confidence", "NOT_FOUND"));
        String agentDid = str(agent.get("did"));

        return new AddressOwnership(
                str(body.getOrDefault("address", address)),
                str(body.getOrDefault("asset", asset)),
                confidence,
                agentDid != null && !"NOT_FOUND".equalsIgnoreCase(confidence),
                agentDid,
                str(agent.get("name")),
                str(agent.get("jurisdiction")),
                str(custodian.get("did")),
                str(custodian.get("name")),
                checkedAs,
                body);
    }


    private static String str(Object value) {
        return value == null ? null : value.toString();
    }
}
