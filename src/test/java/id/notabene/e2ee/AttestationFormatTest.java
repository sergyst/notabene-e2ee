package id.notabene.e2ee;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import org.junit.jupiter.api.Test;

/**
 * Pins the attestation wording and date format against Notabene's documented
 * proof-of-ownership example. The signature is over these exact bytes, so a
 * stray space or a single-digit day would invalidate a legitimate proof.
 */
class AttestationFormatTest {

    /**
     * Verbatim from https://devx.notabene.id/v2.0/docs/create-outgoing-transfers ("Proof of ownership").
     * It is an example there, not a documented requirement - the docs state no rule for the wording.
     */
    private static final String NOTABENE_EXAMPLE =
            "I certify that\n\neip155:1 account 0x9ecfbb28554cade5da58c82469f65f31aebd272b\n\n"
            + "belonged to did:key:z6MksamQq4oVRktkeSDxs6pbixYFUaUca8xgCvnTVLQA5PC5\n\n"
            + "on Thu, 04 Dec 2025 14:20:12 GMT";

    private static String build(String chain, String address, String did, String when) {
        return "I certify that\n\n" + chain + " account " + address + "\n\nbelonged to " + did + "\n\non " + when;
    }

    @Test
    void matchesNotabenesDocumentedExampleExactly() {
        assertThat(build("eip155:1",
                "0x9ecfbb28554cade5da58c82469f65f31aebd272b",
                "did:key:z6MksamQq4oVRktkeSDxs6pbixYFUaUca8xgCvnTVLQA5PC5",
                "Thu, 04 Dec 2025 14:20:12 GMT"))
                .isEqualTo(NOTABENE_EXAMPLE);
    }

    @Test
    void datePadsTheDayToTwoDigits() {
        // Java's built-in RFC_1123 formatter emits "4 Dec", not "04 Dec".
        String formatted = DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.ENGLISH)
                .format(ZonedDateTime.of(2025, 12, 4, 14, 20, 12, 0, ZoneOffset.UTC));

        assertThat(formatted).isEqualTo("Thu, 04 Dec 2025 14:20:12 GMT");
        assertThat(DateTimeFormatter.RFC_1123_DATE_TIME
                .format(ZonedDateTime.of(2025, 12, 4, 14, 20, 12, 0, ZoneOffset.UTC)))
                .as("why we do not use the built-in formatter")
                .contains("4 Dec");
    }

    @Test
    void separatesTheChainFromTheBareAddress() {
        String caip10 = "eip155:1:0x56F55666578B9adb170aEb77eCc8bEA16C7Da116";
        int lastColon = caip10.lastIndexOf(':');

        assertThat(caip10.substring(0, lastColon)).isEqualTo("eip155:1");
        assertThat(caip10.substring(lastColon + 1)).isEqualTo("0x56F55666578B9adb170aEb77eCc8bEA16C7Da116");
    }
}
