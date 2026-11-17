package id.notabene.e2ee.notabene;

/**
 * Blockchain addresses turn up in three shapes across this API - bare
 * ("0x1234…"), CAIP-10 ("eip155:1:0x1234…") and did:pkh
 * ("did:pkh:eip155:1:0x1234…"). v2.1 wallets, proofs, discovery and
 * transfers all take CAIP-10 (a bare EVM address is read as Ethereum mainnet).
 */
public final class Addresses {

    private static final String EVM = "(?i)^0x[0-9a-f]{40}$";
    private static final String CAIP10 = "^[a-z0-9-]{3,8}:[-_a-zA-Z0-9]{1,64}:.+$";

    private Addresses() {
    }

    /** Bare EVM addresses are assumed to be Ethereum mainnet; namespaced ones pass through. */
    public static String toCaip10(String address) {
        String trimmed = address.trim();
        if (trimmed.startsWith("did:pkh:")) {
            return trimmed.substring("did:pkh:".length());
        }
        if (trimmed.matches(EVM)) {
            return "eip155:1:" + trimmed;
        }
        if (trimmed.matches(CAIP10)) {
            return trimmed;
        }
        throw new IllegalArgumentException("Cannot tell which chain \"" + address
                + "\" belongs to. Give a CAIP-10 address such as eip155:1:0x… or a did:pkh:… .");
    }

    /** The did:pkh form, for callers that still want a DID. */
    public static String toDidPkh(String address) {
        String trimmed = address.trim();
        return trimmed.startsWith("did:") ? trimmed : "did:pkh:" + toCaip10(trimmed);
    }
}
