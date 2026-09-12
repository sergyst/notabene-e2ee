package id.notabene.e2ee.crypto;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A P-256 JWK. {@code d} is present only on private keys.
 *
 * Serialises with exactly the member order JOSE expects in an {@code epk}
 * header, and the same shape the JavaScript project writes to keys/*.json, so
 * key files are interchangeable between the two.
 */
public record Jwk(String kty, String crv, String x, String y, String d) {

    public static Jwk publicKey(String x, String y) {
        return new Jwk("EC", "P-256", x, y, null);
    }

    public Jwk publicOnly() {
        return new Jwk(kty, crv, x, y, null);
    }

    public boolean isPrivate() {
        return d != null && !d.isBlank();
    }

    /** Ordered map for the JWE {@code epk} header member: kty, crv, x, y. */
    public Map<String, Object> toPublicMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("kty", kty);
        map.put("crv", crv);
        map.put("x", x);
        map.put("y", y);
        return map;
    }

    @SuppressWarnings("unchecked")
    public static Jwk fromMap(Map<String, ?> map) {
        if (map == null) {
            throw new IllegalArgumentException("Missing JWK");
        }
        Object kty = map.get("kty");
        Object crv = map.get("crv");
        if (!"EC".equals(kty) || !"P-256".equals(crv)) {
            throw new IllegalArgumentException("Expected an EC P-256 JWK, got kty=" + kty + " crv=" + crv);
        }
        return new Jwk("EC", "P-256", str(map, "x"), str(map, "y"), str(map, "d"));
    }

    private static String str(Map<String, ?> map, String key) {
        Object value = map.get(key);
        return value == null ? null : value.toString();
    }
}
