package id.notabene.e2ee.service;

import id.notabene.e2ee.config.NotabeneProperties;
import id.notabene.e2ee.notabene.Addresses;
import id.notabene.e2ee.notabene.NotabeneApiException;
import id.notabene.e2ee.notabene.NotabeneClient;
import id.notabene.e2ee.notabene.Networks;
import id.notabene.e2ee.web.dto.AddOwnershipRequest;
import id.notabene.e2ee.web.dto.AddOwnershipResponse;
import id.notabene.e2ee.web.dto.AddressOwnership;
import id.notabene.e2ee.web.dto.RegisterRequest;
import id.notabene.e2ee.web.dto.RegisterResponse;
import id.notabene.e2ee.web.dto.RegistrationStatus;
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

    // ------------------------------------------------------------ network-aware

    /**
     * Is this address registered, and to whom? The network is explicit so a
     * bare address can never be silently attributed to the wrong chain.
     */
    public RegistrationStatus status(String vaspName, String address, String network, String asset) {
        NotabeneProperties.Vasp caller = properties.requireVasp(vaspName);
        Networks.Network net = Networks.resolve(network);
        String caip10 = Networks.toCaip10(net, address);
        String resolvedAsset = resolveAsset(asset, net);

        Map<String, Object> response = discover(caller, resolvedAsset, caip10, net);
        AddressOwnership owner = toOwnership(response, caip10, resolvedAsset, vaspName);

        RegistrationStatus.VaspRef ref = owner.owned()
                ? new RegistrationStatus.VaspRef(
                        owner.agentDid(),
                        owner.agentName(),
                        owner.agentJurisdiction(),
                        properties.findNameByDid(owner.agentDid()),
                        owner.custodianDid(),
                        owner.custodianName())
                : null;

        log.info("{}: {} on {} -> {}", vaspName, caip10, net.canonical(),
                ref == null ? "not registered" : ref.did());
        return new RegistrationStatus(owner.owned(), address, net.canonical(), caip10,
                resolvedAsset, owner.confidence(), ref);
    }

    /** Register an address to one of our VASPs, then report the resulting status. */
    public RegisterResponse register(RegisterRequest request) {
        NotabeneProperties.Vasp caller = properties.requireVasp(request.vasp());
        Networks.Network net = Networks.resolve(request.network());
        String caip10 = Networks.toCaip10(net, request.address());
        String owner = (request.owner() == null || request.owner().isBlank())
                ? caller.getDid()
                : request.owner();

        Map<String, Object> response = client.confirmRelationship(caller, "did:pkh:" + caip10, owner);
        log.info("{}: registered {} on {} to {}", request.vasp(), caip10, net.canonical(), owner);

        return new RegisterResponse(request.vasp(), owner, caip10, response,
                status(request.vasp(), request.address(), request.network(), request.asset()));
    }

    private String resolveAsset(String asset, Networks.Network net) {
        if (asset != null && !asset.isBlank()) {
            return asset;
        }
        if (net.defaultAsset() != null) {
            return net.defaultAsset();
        }
        throw new IllegalArgumentException("No default asset known for network \"" + net.id()
                + "\". Pass \"asset\" explicitly, e.g. \"" + net.id() + "/slip44:60\".");
    }

    /** Turn Notabene's unsupported-chain error into something that names the cause. */
    private Map<String, Object> discover(NotabeneProperties.Vasp caller, String asset, String caip10,
            Networks.Network net) {
        try {
            return client.discoverAddressOwnership(caller, asset, caip10);
        } catch (NotabeneApiException e) {
            String body = e.getBody() == null ? "" : e.getBody();
            if (body.contains("is not supported or chain is not resolvable")) {
                throw new IllegalArgumentException("Notabene does not support the asset \"" + asset + "\", so "
                        + net.canonical() + " addresses cannot be registered or looked up. Their model needs a "
                        + "fiat price per asset, which testnets do not have. Use a supported mainnet asset, or "
                        + "ask Notabene whether testnet CAIP-2 ids are supported for your tenant.", e);
            }
            if (body.contains("CHAIN_MISMATCH")) {
                throw new IllegalArgumentException("Notabene rejected the pair: asset \"" + asset
                        + "\" does not belong to the chain in \"" + caip10 + "\".", e);
            }
            throw e;
        }
    }

    // ------------------------------------------------------------ original pair

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
