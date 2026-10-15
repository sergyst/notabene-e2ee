package id.notabene.e2ee.notabene;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Blockchain networks by friendly name or CAIP-2 id.
 *
 * Exists so callers can say "ethereum" instead of "eip155:1", and so a bare
 * address can never silently default to the wrong chain - registering
 * 0x1234… on mainnet when you meant Sepolia claims a different address as far
 * as the network is concerned.
 */
public final class Networks {

    /**
     * @param id           CAIP-2 chain id, e.g. "eip155:1"
     * @param canonical    the name this project prefers for it
     * @param defaultAsset CAIP-19 asset used for ownership lookups on this chain
     */
    public record Network(String id, String canonical, String defaultAsset) {
    }

    private static final Map<String, Network> BY_NAME = new LinkedHashMap<>();

    private static void register(Network network, String... aliases) {
        BY_NAME.put(network.canonical(), network);
        BY_NAME.put(network.id(), network);
        for (String alias : aliases) {
            BY_NAME.put(alias, network);
        }
    }

    static {
        register(new Network("eip155:1", "ethereum", "eip155:1/slip44:60"), "eth", "mainnet");
        register(new Network("eip155:11155111", "sepolia", "eip155:11155111/slip44:60"));
        register(new Network("eip155:17000", "holesky", "eip155:17000/slip44:60"));
        register(new Network("eip155:137", "polygon", "eip155:137/slip44:966"), "matic");
        register(new Network("bip122:000000000019d6689c085ae165831e93", "bitcoin",
                "bip122:000000000019d6689c085ae165831e93/slip44:0"), "btc");
    }

    private Networks() {
    }

    /** A friendly name ("sepolia"), or a CAIP-2 id ("eip155:11155111") for anything not listed. */
    public static Network resolve(String network) {
        if (network == null || network.isBlank()) {
            throw new IllegalArgumentException("network is required, e.g. \"ethereum\" or \"eip155:1\". Known: "
                    + String.join(", ", knownNames()));
        }
        String key = network.trim().toLowerCase();
        Network known = BY_NAME.get(key);
        if (known != null) {
            return known;
        }
        // Any valid CAIP-2 passes through; we just cannot guess its native asset.
        if (key.matches("^[a-z0-9-]{3,8}:[-_a-zA-Z0-9]{1,64}$")) {
            return new Network(key, key, null);
        }
        throw new IllegalArgumentException("Unknown network \"" + network + "\". Use a CAIP-2 id such as "
                + "\"eip155:1\", or one of: " + String.join(", ", knownNames()));
    }

    /** Join a network and an address into the CAIP-10 form the API expects. */
    public static String toCaip10(Network network, String address) {
        String trimmed = address.trim();
        String bare = trimmed.startsWith("did:pkh:") ? trimmed.substring("did:pkh:".length()) : trimmed;

        int lastColon = bare.lastIndexOf(':');
        if (lastColon > 0) {
            String chain = bare.substring(0, lastColon);
            if (!chain.equalsIgnoreCase(network.id())) {
                throw new IllegalArgumentException("Address names chain \"" + chain + "\" but network is \""
                        + network.id() + "\". Give the address without a chain prefix, or make them agree.");
            }
            return network.id() + ":" + bare.substring(lastColon + 1);
        }
        return network.id() + ":" + bare;
    }

    public static java.util.List<String> knownNames() {
        return BY_NAME.entrySet().stream()
                .filter(e -> e.getKey().equals(e.getValue().canonical()))
                .map(Map.Entry::getKey)
                .toList();
    }
}
