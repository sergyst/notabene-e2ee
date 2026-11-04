package id.notabene.e2ee.service;

import id.notabene.e2ee.config.NotabeneProperties;
import id.notabene.e2ee.notabene.Addresses;
import id.notabene.e2ee.notabene.NotabeneApiException;
import id.notabene.e2ee.notabene.NotabeneClient;
import id.notabene.e2ee.notabene.Networks;
import id.notabene.e2ee.web.dto.AddOwnershipRequest;
import id.notabene.e2ee.web.dto.AddOwnershipResponse;
import id.notabene.e2ee.web.dto.AddressOwnership;
import id.notabene.e2ee.web.dto.Attestation;
import id.notabene.e2ee.web.dto.OwnershipProof;
import id.notabene.e2ee.web.dto.RegisterRequest;
import id.notabene.e2ee.web.dto.RegisterResponse;
import id.notabene.e2ee.web.dto.RegistrationStatus;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
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
@Slf4j
public class AddressOwnershipService {

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
        String owner = caller.getDid();

        Map<String, Object> response = client.confirmRelationship(
                caller, "did:pkh:" + caip10, owner, proofBody(request.proof(), caip10));
        log.info("{}: registered {} on {} to {} with a {} proof", request.vasp(), caip10, net.canonical(), owner,
                proofType(request.proof()));

        return new RegisterResponse(request.vasp(), owner, caip10, response,
                status(request.vasp(), request.address(), request.network(), request.asset()));
    }

    /**
     * The exact message to sign. Mirrors the format in Notabene's proof-of-
     * ownership example; it carries a timestamp, so the caller must sign the
     * string we return rather than rebuild it.
     */
    public Attestation initiate(String vaspName, String address, String network) {
        NotabeneProperties.Vasp caller = properties.requireVasp(vaspName);
        Networks.Network net = Networks.resolve(network);
        String caip10 = Networks.toCaip10(net, address);
        String did = caller.getDid();

        int lastColon = caip10.lastIndexOf(':');
        String chain = caip10.substring(0, lastColon);
        String bare = caip10.substring(lastColon + 1);
        String when = DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.ENGLISH)
                .format(ZonedDateTime.now(ZoneOffset.UTC));

        String message = "I certify that\n\n" + chain + " account " + bare
                + "\n\nbelonged to " + did + "\n\non " + when;

        return new Attestation(message, caip10, did, net.canonical(), "eip-191",
                "Sign this message verbatim with the address's private key, then POST it to "
                        + "/api/register/complete as proof.attestation together with proof.signature. "
                        + "This server does not verify the signature - Notabene does.");
    }

    private static String proofType(OwnershipProof proof) {
        return (proof.type() == null || proof.type().isBlank()) ? "eip-191" : proof.type();
    }

    /** Build the PATCH body carrying the signed proof. */
    private static Map<String, Object> proofBody(OwnershipProof proof, String caip10) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("type", proofType(proof));
        out.put("address", caip10);
        // Both identify the ADDRESS, not its owner: Notabene checks proof.did
        // against the "from" side of the relationship and rejects a mismatch
        // with "Proof did does not match 'from' query".
        out.put("did", "did:pkh:" + caip10);
        out.put("attestation", proof.attestation());
        out.put("proof", proof.signature());
        out.put("status", (proof.status() == null || proof.status().isBlank()) ? "verified" : proof.status());
        if (proof.xpub() != null && !proof.xpub().isBlank()) {
            out.put("xpub", proof.xpub());
        }
        if (proof.chainSpecificData() != null && !proof.chainSpecificData().isEmpty()) {
            out.put("chainSpecificData", proof.chainSpecificData());
        }
        return Map.of("proof", out);
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
