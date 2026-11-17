package id.notabene.e2ee.service;

import id.notabene.e2ee.config.NotabeneProperties;
import id.notabene.e2ee.notabene.Addresses;
import id.notabene.e2ee.notabene.NotabeneClient;
import id.notabene.e2ee.notabene.Networks;
import id.notabene.e2ee.web.dto.Attestation;
import id.notabene.e2ee.web.dto.OwnershipProof;
import id.notabene.e2ee.web.dto.RegisterRequest;
import id.notabene.e2ee.web.dto.RegisterResponse;
import id.notabene.e2ee.web.dto.RegistrationStatus;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Set;
import java.util.Locale;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Who owns a blockchain address, and registering one for yourself.
 *
 * Registration follows Notabene v2.1: the address is registered under a
 * customer (POST /api/v1/wallets) and the customer's control of it is then
 * proven (POST /api/v1/customers/{customer}/wallets/{address}/proofs).
 * Lookup is POST /api/v1/wallet-ownerships/discover.
 */
@Service
@Slf4j
public class AddressOwnershipService {

    /** Proof types that carry an attestation rather than a signature. */
    private static final Set<String> NON_SIGNATURE_TYPES = Set.of("self-declaration", "screenshot");

    private final NotabeneProperties properties;
    private final NotabeneClient client;
    private final CustomerService customers;

    public AddressOwnershipService(NotabeneProperties properties, NotabeneClient client,
            CustomerService customers) {
        this.properties = properties;
        this.client = client;
        this.customers = customers;
    }

    /**
     * Is this address registered, and to whom? The network is explicit so a
     * bare address can never be silently attributed to the wrong chain.
     */
    public RegistrationStatus status(String vaspName, String address, String network) {
        NotabeneProperties.Vasp caller = properties.requireVasp(vaspName);
        Networks.Network net = Networks.resolve(network);
        String caip10 = Networks.toCaip10(net, address);

        Map<String, Object> owner = client.discoverWalletOwnership(caller, caip10);
        if (owner == null) {
            log.info("{}: {} on {} -> not registered", vaspName, caip10, net.canonical());
            return new RegistrationStatus(false, address, net.canonical(), caip10, null, null);
        }

        String ownerDid = str(owner.get("owner"));
        String custodianDid = str(owner.get("custodian"));
        Map<String, Object> entity = entity(caller, ownerDid);
        String custodianName = custodianDid == null || custodianDid.equals(ownerDid)
                ? str(entity.get("name"))
                : str(entity(caller, custodianDid).get("name"));

        RegistrationStatus.VaspRef ref = new RegistrationStatus.VaspRef(
                ownerDid,
                str(entity.get("name")),
                str(entity.get("jurisdiction")),
                properties.findNameByDid(ownerDid),
                custodianDid,
                custodianName);
        log.info("{}: {} on {} -> {} (source {})", vaspName, caip10, net.canonical(), ownerDid,
                owner.get("source"));
        return new RegistrationStatus(true, address, net.canonical(), caip10, str(owner.get("source")), ref);
    }

    /**
     * Register an address under the VASP's customer, submit the proof, then
     * report the resulting status.
     */
    public RegisterResponse register(RegisterRequest request) {
        NotabeneProperties.Vasp caller = properties.requireVasp(request.vasp());
        Networks.Network net = Networks.resolve(request.network());
        String caip10 = Networks.toCaip10(net, request.address());
        OwnershipProof proof = request.proof();
        validate(proof);

        String customer = customers.ensure(caller);

        Map<String, Object> wallet = new LinkedHashMap<>();
        wallet.put("address", caip10);
        wallet.put("customer_id", customer);
        wallet.put("managed", Boolean.TRUE.equals(request.managed()));
        Map<String, Object> walletResponse = client.registerWallet(caller, wallet);

        Map<String, Object> proofResponse = client.submitWalletProof(caller, customer, caip10, proofBody(proof));
        log.info("{}: registered {} on {} under {} with a {} proof ({})", request.vasp(), caip10, net.canonical(),
                customer, proof.type(), proofResponse.get("status"));

        return new RegisterResponse(request.vasp(), customer, caip10, walletResponse, proofResponse,
                status(request.vasp(), request.address(), request.network()));
    }

    /**
     * A message to sign. This is the example text from the v2.0 proof-of-ownership
     * guide, kept as-is. The v2.1 docs say no wording is required but don't give a
     * format for eip-191 or bip-322, so whether Notabene accepts this exact text is
     * unconfirmed. It carries a timestamp, so the caller must sign the string we
     * return rather than rebuild it.
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
                        + "This server does not verify the signature - Notabene does. For a "
                        + "self-declaration or screenshot there is nothing to sign: send proof.type and "
                        + "proof.attestation only.");
    }

    private static void validate(OwnershipProof proof) {
        String type = proof.type().trim();
        if (NON_SIGNATURE_TYPES.contains(type)) {
            if (blank(proof.attestation())) {
                throw new IllegalArgumentException("A " + type + " proof needs proof.attestation.");
            }
        } else if (blank(proof.signature())) {
            throw new IllegalArgumentException("A " + type + " proof needs proof.signature.");
        }
        if (blank(proof.xpub()) == "bip-137-xpub".equals(type)) {
            throw new IllegalArgumentException("proof.xpub is required for, and only valid with, bip-137-xpub.");
        }
    }

    /** The proofs body: additionalProperties is false, so send nothing but documented fields. */
    private static Map<String, Object> proofBody(OwnershipProof proof) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("type", proof.type().trim());
        putIfPresent(out, "attestation", proof.attestation());
        putIfPresent(out, "signature", proof.signature());
        putIfPresent(out, "wallet_provider", proof.walletProvider());
        putIfPresent(out, "xpub", proof.xpub());
        if (proof.chainData() != null && !proof.chainData().isEmpty()) {
            out.put("chain_data", proof.chainData());
        }
        return out;
    }

    private static void putIfPresent(Map<String, Object> out, String key, String value) {
        if (!blank(value)) {
            out.put(key, value.trim());
        }
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    /** Name and jurisdiction from the network directory; a miss is not worth failing a lookup over. */
    private Map<String, Object> entity(NotabeneProperties.Vasp caller, String did) {
        if (did == null) {
            return Map.of();
        }
        try {
            return client.getNetworkEntity(caller, did);
        } catch (RuntimeException e) {
            log.debug("no directory entry for {}: {}", did, e.getMessage());
            return Map.of();
        }
    }

    private static String str(Object value) {
        return value == null ? null : value.toString();
    }
}
