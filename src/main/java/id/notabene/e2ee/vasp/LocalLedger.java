package id.notabene.e2ee.vasp;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * An in-memory stand-in for Notabene, so the whole encrypt -> store -> decrypt
 * path can be exercised before a "#pii" key is published in the DIDDoc.
 *
 * It deliberately stores whatever it is given and hands it back untouched -
 * which is the point: with customer-managed encryption the platform only ever
 * holds ciphertext.
 */
@Component
public class LocalLedger {

    public record Entry(
            String id,
            String fromVasp,
            String toVasp,
            String originatorDid,
            String beneficiaryDid,
            String asset,
            String amount,
            String mode,
            String recipientKid,
            Instant createdAt,
            Object encryptedIvms101) {
    }

    private final Map<String, Entry> entries = new ConcurrentHashMap<>();

    public Entry add(Entry entry) {
        entries.put(entry.id(), entry);
        return entry;
    }

    /** Everything this VASP can see: what it sent, and what was sent to it. */
    public List<Entry> forVasp(String vaspName) {
        List<Entry> out = new ArrayList<>();
        for (Entry entry : entries.values()) {
            if (entry.fromVasp().equals(vaspName) || entry.toVasp().equals(vaspName)) {
                out.add(entry);
            }
        }
        out.sort(Comparator.comparing(Entry::createdAt).reversed());
        return out;
    }

    public Entry get(String id) {
        return entries.get(id);
    }

    public int size() {
        return entries.size();
    }

    public void clear() {
        entries.clear();
    }
}
