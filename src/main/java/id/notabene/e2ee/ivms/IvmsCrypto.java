package id.notabene.e2ee.ivms;

import id.notabene.e2ee.crypto.EcdhEsJwe;
import id.notabene.e2ee.crypto.Jwk;
import id.notabene.e2ee.crypto.PiiCrypto;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * Field-level and branch-level encryption over an IVMS101 payload.
 *
 * Decryption auto-detects: any string that parses as a JWE is decrypted and
 * JSON-parsed back into place, so it handles either shape without being told,
 * and a payload mixing plaintext and encrypted values still works.
 */
@Component
public class IvmsCrypto {

    /** One JWE produced or consumed, with the JSON path it sits at. */
    public record Part(String path, Object value, String jwe) {
    }

    public record Leaf(String path, Object value) {
    }

    public record EncryptResult(Object payload, List<Part> parts) {
    }

    public record DecryptResult(Object payload, List<Part> parts) {
    }

    private final PiiCrypto piiCrypto;

    public IvmsCrypto(PiiCrypto piiCrypto) {
        this.piiCrypto = piiCrypto;
    }

    // ------------------------------------------------------------------ encrypt

    public EncryptResult encrypt(Map<String, Object> ivms, PiiMode mode, Jwk recipientJwk, String recipientKid,
            String senderDid) {
        List<Part> parts = new ArrayList<>();

        if (mode == PiiMode.FIELD) {
            Object payload = mapLeaves(ivms, "$", (value, path) -> {
                String jwe = piiCrypto.encryptValue(value, recipientJwk, recipientKid, senderDid);
                parts.add(new Part(path, value, jwe));
                return jwe;
            });
            return new EncryptResult(payload, parts);
        }

        // One JWE per top-level branch: originator, beneficiary, anything else present.
        Map<String, Object> payload = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : ivms.entrySet()) {
            String jwe = piiCrypto.encryptValue(entry.getValue(), recipientJwk, recipientKid, senderDid);
            parts.add(new Part("$." + entry.getKey(), entry.getValue(), jwe));
            payload.put(entry.getKey(), jwe);
        }
        return new EncryptResult(payload, parts);
    }

    // ------------------------------------------------------------------ decrypt

    public DecryptResult decrypt(Object ivms, Jwk privateJwk, String expectedSenderDid, String expectedRecipientKid) {
        List<Part> parts = new ArrayList<>();
        Object payload = mapLeaves(ivms, "$", (value, path) -> {
            if (!EcdhEsJwe.looksLikeJwe(value)) {
                return value;
            }
            String jwe = (String) value;
            Object decrypted = piiCrypto.decryptValue(jwe, privateJwk, expectedSenderDid, expectedRecipientKid);
            parts.add(new Part(path, decrypted, jwe));
            return decrypted;
        });
        return new DecryptResult(payload, parts);
    }

    // ------------------------------------------------------------------ walking

    @FunctionalInterface
    private interface LeafTransform {
        Object apply(Object value, String path);
    }

    /** Depth-first walk that replaces every non-container leaf via the transform. */
    private Object mapLeaves(Object node, String path, LeafTransform transform) {
        if (node instanceof Map<?, ?> map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                String key = String.valueOf(entry.getKey());
                out.put(key, mapLeaves(entry.getValue(), path + "." + key, transform));
            }
            return out;
        }
        if (node instanceof List<?> list) {
            List<Object> out = new ArrayList<>(list.size());
            for (int i = 0; i < list.size(); i++) {
                out.add(mapLeaves(list.get(i), path + "[" + i + "]", transform));
            }
            return out;
        }
        return transform.apply(node, path);
    }

    /** Flatten to [path, value] pairs for logging - independent of how it was encrypted. */
    public List<Leaf> flattenLeaves(Object node) {
        List<Leaf> out = new ArrayList<>();
        collectLeaves(node, "$", out);
        return out;
    }

    private void collectLeaves(Object node, String path, List<Leaf> out) {
        if (node instanceof Map<?, ?> map) {
            map.forEach((key, value) -> collectLeaves(value, path + "." + key, out));
        } else if (node instanceof List<?> list) {
            for (int i = 0; i < list.size(); i++) {
                collectLeaves(list.get(i), path + "[" + i + "]", out);
            }
        } else {
            out.add(new Leaf(path, node));
        }
    }

    // ------------------------------------------------------------------ lookup

    /** Find the ivms101 object inside a Notabene transfer response, wherever they put it. */
    @SuppressWarnings("unchecked")
    public Map<String, Object> findIvms(Object transfer) {
        Set<Object> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        Deque<Object> stack = new ArrayDeque<>();
        if (transfer != null) {
            stack.push(transfer);
        }

        while (!stack.isEmpty()) {
            Object node = stack.pop();
            if (node == null || !seen.add(node)) {
                continue;
            }
            if (node instanceof Map<?, ?> map) {
                if (map.get("ivms101") instanceof Map<?, ?> nested) {
                    return (Map<String, Object>) nested;
                }
                // Branch mode leaves originator as a JWE string, field mode as an object.
                Object originator = map.get("originator");
                boolean isPayload = EcdhEsJwe.looksLikeJwe(originator)
                        || (originator instanceof Map<?, ?> o
                                && (o.containsKey("originatorPerson") || o.containsKey("originatorPersons")));
                if (isPayload) {
                    return (Map<String, Object>) map;
                }
                map.values().forEach(value -> {
                    if (value != null) {
                        stack.push(value);
                    }
                });
            } else if (node instanceof List<?> list) {
                list.forEach(value -> {
                    if (value != null) {
                        stack.push(value);
                    }
                });
            }
        }
        return null;
    }
}
