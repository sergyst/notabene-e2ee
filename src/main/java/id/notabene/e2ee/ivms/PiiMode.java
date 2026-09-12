package id.notabene.e2ee.ivms;

import java.util.Arrays;
import java.util.stream.Collectors;

/** How much of the IVMS101 payload goes into each JWE. */
public enum PiiMode {

    /**
     * One JWE per top-level branch, so the body is
     * { "ivms101": { "originator": "<JWE>", "beneficiary": "<JWE>" } }.
     * Nothing about the person leaks - not how many addresses they have, not
     * which optional fields are populated.
     */
    BRANCH,

    /**
     * One JWE per leaf value, keeping the IVMS101 tree visible. This is the
     * shape in Notabene's own reference examples, and the only one that lets
     * the platform validate a payload it cannot read.
     */
    FIELD;

    public static PiiMode from(String value) {
        if (value == null || value.isBlank()) {
            return BRANCH;
        }
        try {
            return PiiMode.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            String allowed = Arrays.stream(values())
                    .map(mode -> mode.name().toLowerCase())
                    .collect(Collectors.joining(", "));
            throw new IllegalArgumentException(
                    "Unknown PII encryption mode: \"" + value + "\". Use one of: " + allowed);
        }
    }

    public String lower() {
        return name().toLowerCase();
    }
}
