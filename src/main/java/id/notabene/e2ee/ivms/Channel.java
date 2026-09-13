package id.notabene.e2ee.ivms;

/** Where a Travel Rule message lives. */
public enum Channel {

    /** The real Notabene Transact V2 API. */
    NOTABENE,

    /**
     * An in-memory stand-in on this server. Same encryption, same IVMS101, no
     * network - useful before your "#pii" key is published in the DIDDoc, which
     * is what Notabene needs before it will accept an encrypted presentation.
     */
    LOCAL;

    public static Channel from(String value) {
        if (value == null || value.isBlank()) {
            return NOTABENE;
        }
        try {
            return Channel.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "Unknown channel: \"" + value + "\". Use one of: notabene, local");
        }
    }

    public String lower() {
        return name().toLowerCase();
    }
}
