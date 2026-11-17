package id.notabene.e2ee.web.dto;

/**
 * Whether an address is registered, and to whom.
 *
 * @param registered true when a VASP owns it; vasp is null otherwise
 * @param source     how Notabene established ownership (e.g. AddressHash); null when not registered
 * @param caip10     what was actually queried, after normalisation
 */
public record RegistrationStatus(
        boolean registered,
        String address,
        String network,
        String caip10,
        String source,
        VaspRef vasp) {

    /**
     * @param configuredName the local name for this VASP, or null when the owner
     *                       is a counterparty rather than one of ours
     */
    public record VaspRef(
            String did,
            String name,
            String jurisdiction,
            String configuredName,
            String custodianDid,
            String custodianName) {
    }
}
