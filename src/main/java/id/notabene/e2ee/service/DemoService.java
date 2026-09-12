package id.notabene.e2ee.service;

import id.notabene.e2ee.crypto.EcdhEsJwe;
import id.notabene.e2ee.ivms.IvmsCrypto;
import id.notabene.e2ee.ivms.PiiMode;
import id.notabene.e2ee.ivms.SamplePii;
import id.notabene.e2ee.vasp.VaspKeyStore;
import id.notabene.e2ee.vasp.VaspKeypair;
import id.notabene.e2ee.web.dto.DemoReport;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * The offline round trip, port of scripts/demo-local.js. No credentials, no
 * network:
 *
 *   vaspA --encrypt--> [what Notabene would store] --> vaspB --decrypt-->
 *
 * Everything the JavaScript version logs is returned as JSON as well, so you
 * can see it in the HTTP response and in the application log.
 */
@Service
public class DemoService {

    private static final Logger log = LoggerFactory.getLogger(DemoService.class);

    private static final String DEMO_SENDER_DID = "did:web:vasps.id:vaspa";
    private static final String DEMO_RECIPIENT_DID = "did:web:vasps.id:vaspb";
    private static final String DEMO_THIRD_PARTY_DID = "did:web:notabene.id:platform";

    private final IvmsCrypto ivmsCrypto;
    private final SamplePii samplePii;
    private final VaspKeyStore keyStore;

    public DemoService(IvmsCrypto ivmsCrypto, SamplePii samplePii, VaspKeyStore keyStore) {
        this.ivmsCrypto = ivmsCrypto;
        this.samplePii = samplePii;
        this.keyStore = keyStore;
    }

    public DemoReport run(PiiMode mode) {
        // Throwaway keys, so the demo never touches keys/*.json or the network.
        VaspKeypair vaspB = keyStore.generate("vaspB", DEMO_RECIPIENT_DID);
        VaspKeypair thirdParty = keyStore.generate("thirdParty", DEMO_THIRD_PARTY_DID);
        Map<String, Object> pii = samplePii.get();

        log.info("=== demo: mode={} recipient={} ===", mode.lower(), vaspB.kid());

        // 1 - vaspA encrypts to vaspB's published key only.
        IvmsCrypto.EncryptResult encrypted = ivmsCrypto.encrypt(
                pii, mode, vaspB.publicJwk(), vaspB.kid(), DEMO_SENDER_DID);
        log.info("vaspA encrypted {} JWE(s) [{}]", encrypted.parts().size(), mode.lower());

        Map<String, Object> header = EcdhEsJwe.readHeader(encrypted.parts().get(0).jwe());

        // 2 - this is exactly the body of POST /entities/:did/tx/:id/presentation.
        Map<String, Object> wirePayload = new LinkedHashMap<>();
        wirePayload.put("ivms101", encrypted.payload());

        // A third party holding its own key cannot read any of it.
        String thirdPartyError;
        try {
            ivmsCrypto.decrypt(encrypted.payload(), thirdParty.privateJwk(), null, null);
            thirdPartyError = null;
            log.error("a third party could read the PII - that should never happen");
        } catch (RuntimeException e) {
            thirdPartyError = e.getMessage();
            log.info("third party decryption correctly failed: {}", thirdPartyError);
        }

        // 3 - vaspB decrypts with the private key that never left it, and
        // verifies the apu/apv bindings name who we expect.
        IvmsCrypto.DecryptResult decrypted = ivmsCrypto.decrypt(
                encrypted.payload(), vaspB.privateJwk(), DEMO_SENDER_DID, vaspB.kid());
        log.info("vaspB decrypted {} JWE(s)", decrypted.parts().size());

        // 4 - sent versus received, leaf by leaf.
        List<DemoReport.Comparison> comparisons = compare(pii, decrypted.payload());
        long mismatches = comparisons.stream().filter(c -> !c.match()).count();
        boolean deepEqual = Objects.equals(decrypted.payload(), pii);

        for (DemoReport.Comparison c : comparisons) {
            log.info("  {} {} sent={} got={}", c.match() ? "=" : "X", c.path(), c.sent(), c.received());
        }
        if (deepEqual && mismatches == 0) {
            log.info("VERDICT: PII decrypted by vaspB is deep-equal to the PII vaspA sent");
        } else {
            log.error("VERDICT: mismatch between sent and decrypted PII ({} field(s) differ)", mismatches);
        }

        // 6 - the other mode round-trips too: same crypto, different granularity.
        PiiMode otherMode = mode == PiiMode.BRANCH ? PiiMode.FIELD : PiiMode.BRANCH;
        IvmsCrypto.EncryptResult otherEncrypted = ivmsCrypto.encrypt(
                pii, otherMode, vaspB.publicJwk(), vaspB.kid(), DEMO_SENDER_DID);
        IvmsCrypto.DecryptResult otherDecrypted = ivmsCrypto.decrypt(
                otherEncrypted.payload(), vaspB.privateJwk(), null, null);
        boolean otherRoundTrips = Objects.equals(otherDecrypted.payload(), pii);
        String otherShape = otherEncrypted.payload() instanceof Map<?, ?> m
                && m.get("originator") instanceof String
                        ? "a single JWE string"
                        : "an object of JWE leaves";
        log.info("{} mode round-trips: {} (ivms101.originator is {})",
                otherMode.lower(), otherRoundTrips, otherShape);

        List<DemoReport.EncryptedPart> parts = encrypted.parts().stream()
                .map(p -> new DemoReport.EncryptedPart(p.path(), truncate(p.jwe())))
                .toList();

        return new DemoReport(
                mode.lower(),
                vaspB.kid(),
                vaspB.publicKeyHex(),
                pii,
                parts,
                header,
                wirePayload,
                thirdPartyError,
                decrypted.payload(),
                comparisons,
                deepEqual && mismatches == 0,
                (int) mismatches,
                new DemoReport.OtherMode(otherMode.lower(), otherRoundTrips, otherShape));
    }

    private List<DemoReport.Comparison> compare(Object sent, Object received) {
        List<IvmsCrypto.Leaf> sentLeaves = ivmsCrypto.flattenLeaves(sent);
        Map<String, Object> receivedByPath = new LinkedHashMap<>();
        ivmsCrypto.flattenLeaves(received).forEach(leaf -> receivedByPath.put(leaf.path(), leaf.value()));

        List<DemoReport.Comparison> out = new ArrayList<>(sentLeaves.size());
        for (IvmsCrypto.Leaf leaf : sentLeaves) {
            Object got = receivedByPath.get(leaf.path());
            out.add(new DemoReport.Comparison(
                    shortPath(leaf.path()), leaf.value(), got, Objects.equals(leaf.value(), got)));
        }
        return out;
    }

    /** Trim the long IVMS101 paths so the table stays readable. */
    private static String shortPath(String path) {
        return path
                .replaceFirst("^\\$\\.?", "")
                .replace("originatorPerson[0].naturalPerson.", "orig.")
                .replace("beneficiaryPerson[0].naturalPerson.", "benf.")
                .replace("name.nameIdentifier[0].", "");
    }

    private static String truncate(String value) {
        return value.length() <= 72 ? value : value.substring(0, 72) + "...";
    }
}
