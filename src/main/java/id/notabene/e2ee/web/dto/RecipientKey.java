package id.notabene.e2ee.web.dto;

import java.util.Map;

/**
 * Which public key to encrypt the PII to.
 *
 * Omit it and the server asks Notabene for the counterparty's published key,
 * which is the normal path. Supply it when that lookup cannot work - for
 * instance when the counterparty's did:web does not resolve, so
 * GET /entities/:did/public-keys answers NO_ENCRYPTION_KEYS - or when you want
 * to pin the key yourself rather than trust a directory lookup.
 *
 * End-to-end encryption needs the recipient's public key either way: doing the
 * encryption on your own server changes who holds the private key, not whether
 * you have to discover the public one.
 *
 * @param source        "notabene" (default), "local" (this server's keys/&lt;to&gt;.json),
 *                      or "explicit" (use the key given here)
 * @param kid           key id bound into apv; defaults to "&lt;recipient DID&gt;#&lt;key-fragment&gt;"
 * @param publicKeyHex  compressed or uncompressed SEC1 P-256 point
 * @param publicKeyJwk  the same key as a JWK, if you prefer
 */
public record RecipientKey(
        String source,
        String kid,
        String publicKeyHex,
        Map<String, Object> publicKeyJwk) {

    public boolean hasExplicitMaterial() {
        return (publicKeyHex != null && !publicKeyHex.isBlank()) || (publicKeyJwk != null && !publicKeyJwk.isEmpty());
    }
}
