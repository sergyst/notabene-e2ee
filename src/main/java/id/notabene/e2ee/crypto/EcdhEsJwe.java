package id.notabene.e2ee.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import tools.jackson.databind.ObjectMapper;

/**
 * Notabene-compatible JWE, written from scratch so you own every step of the
 * encryption. Mirrors:
 *   https://devx.notabene.id/docs/encryption-workflow-1
 *   https://devx.notabene.id/docs/decryption-workflow-1
 * and their cross-language reference implementation:
 *   https://gitlab.com/notabene/open-source/notabene-encryption-examples
 *
 * Scheme: JWE compact, alg = ECDH-ES (direct key agreement, empty
 *         encrypted_key), enc = A256GCM, curve = P-256, CEK derived with
 *         RFC 7518 ConcatKDF, apu = SHA-256(sender DID),
 *         apv = SHA-256(recipient key id).
 */
public final class EcdhEsJwe {

    public static final String ALG = "ECDH-ES";
    public static final String ENC = "A256GCM";

    private static final int IV_BYTES = 12;
    private static final int TAG_BYTES = 16;
    private static final int TAG_BITS = TAG_BYTES * 8;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final ObjectMapper JSON = new ObjectMapper();

    private EcdhEsJwe() {
    }

    /**
     * Encrypt one value for one recipient.
     *
     * @param plaintext     the bytes to protect, already JSON-serialised by {@link PiiCrypto}
     * @param recipientJwk  the recipient's published P-256 public key
     * @param recipientKid  e.g. "did:web:vasps.id:vaspb#pii", bound into apv
     * @param senderDid     your entity DID, bound into apu; may be null
     * @return compact JWE: header..iv.ciphertext.tag
     */
    public static String encrypt(String plaintext, Jwk recipientJwk, String recipientKid, String senderDid) {
        // Step 2 - a fresh ephemeral key pair per value, never reused.
        KeyPair ephemeral = P256.generateKeyPair();
        Jwk epk = P256.toJwk((ECPublicKey) ephemeral.getPublic());

        // Step 3 - ECDH against the recipient's published key.
        byte[] sharedSecret = deriveSharedSecret(
                (ECPrivateKey) ephemeral.getPrivate(), P256.toPublicKey(recipientJwk));

        // Step 4 - ConcatKDF with the privacy-preserving bindings.
        byte[] apu = senderDid == null ? null : ConcatKdf.sha256(senderDid);
        byte[] apv = recipientKid == null ? null : ConcatKdf.sha256(recipientKid);
        byte[] cek = ConcatKdf.deriveKey(sharedSecret, ENC, apu, apv, 256);

        // Step 5 - protected header, then AES-256-GCM with the header as AAD.
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", ALG);
        header.put("enc", ENC);
        header.put("typ", "JWE");
        header.put("epk", epk.toPublicMap());
        if (apu != null) {
            header.put("apu", Base64Url.encode(apu));
        }
        if (apv != null) {
            header.put("apv", Base64Url.encode(apv));
        }
        if (recipientKid != null) {
            header.put("kid", recipientKid);
        }
        String headerB64 = Base64Url.encode(JSON.writeValueAsString(header));

        byte[] iv = new byte[IV_BYTES];
        RANDOM.nextBytes(iv);
        byte[] sealed = aesGcm(Cipher.ENCRYPT_MODE, cek, iv, headerB64,
                plaintext.getBytes(StandardCharsets.UTF_8));

        byte[] ciphertext = new byte[sealed.length - TAG_BYTES];
        byte[] tag = new byte[TAG_BYTES];
        System.arraycopy(sealed, 0, ciphertext, 0, ciphertext.length);
        System.arraycopy(sealed, ciphertext.length, tag, 0, TAG_BYTES);

        return headerB64 + ".." + Base64Url.encode(iv) + "." + Base64Url.encode(ciphertext) + "."
                + Base64Url.encode(tag);
    }

    /**
     * Decrypt a compact JWE with your own private key. Nothing here talks to
     * Notabene - the ciphertext is opaque to them.
     *
     * @param expectedSenderDid    if given, apu must equal SHA-256 of it
     * @param expectedRecipientKid if given, apv must equal SHA-256 of it
     */
    public static String decrypt(String jwe, Jwk privateJwk, String expectedSenderDid, String expectedRecipientKid) {
        String[] parts = jwe.split("\\.", -1);
        if (parts.length != 5) {
            throw new IllegalArgumentException("Invalid JWE compact serialization");
        }
        String headerB64 = parts[0];
        if (!parts[1].isEmpty()) {
            throw new IllegalArgumentException("Expected direct ECDH-ES (empty encrypted_key)");
        }

        Map<String, Object> header = readHeader(jwe);
        if (!ALG.equals(header.get("alg")) || !ENC.equals(header.get("enc"))) {
            throw new IllegalArgumentException(
                    "Unsupported algorithm: " + header.get("alg") + "/" + header.get("enc"));
        }

        Object epkValue = header.get("epk");
        if (!(epkValue instanceof Map<?, ?> epkMap)) {
            throw new IllegalArgumentException("Invalid or missing ephemeral public key");
        }
        @SuppressWarnings("unchecked")
        Jwk epk = Jwk.fromMap((Map<String, ?>) epkMap);

        // P256.toPublicKey checks the ephemeral point is actually on the curve.
        byte[] sharedSecret = deriveSharedSecret(P256.toPrivateKey(privateJwk), P256.toPublicKey(epk));

        // Unknown-key-share protection: the bindings must name who we think they name.
        byte[] apu = header.get("apu") == null ? new byte[0] : Base64Url.decode(header.get("apu").toString());
        byte[] apv = header.get("apv") == null ? new byte[0] : Base64Url.decode(header.get("apv").toString());
        if (expectedSenderDid != null && header.get("apu") != null
                && !MessageDigest.isEqual(apu, ConcatKdf.sha256(expectedSenderDid))) {
            throw new IllegalArgumentException("APU mismatch - potential unknown-key-share attack");
        }
        if (expectedRecipientKid != null && header.get("apv") != null
                && !MessageDigest.isEqual(apv, ConcatKdf.sha256(expectedRecipientKid))) {
            throw new IllegalArgumentException("APV mismatch - this message was not addressed to that key");
        }

        byte[] cek = ConcatKdf.deriveKey(sharedSecret, ENC, apu, apv, 256);

        byte[] ciphertext = Base64Url.decode(parts[3]);
        byte[] tag = Base64Url.decode(parts[4]);
        byte[] sealed = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, sealed, 0, ciphertext.length);
        System.arraycopy(tag, 0, sealed, ciphertext.length, tag.length);

        byte[] plaintext;
        try {
            plaintext = aesGcm(Cipher.DECRYPT_MODE, cek, Base64Url.decode(parts[2]), headerB64, sealed);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException(
                    "AES-GCM authentication failed - wrong private key, or the ciphertext was tampered with", e);
        }
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    /** True for anything shaped like the compact JWEs we produce. */
    public static boolean looksLikeJwe(Object value) {
        if (!(value instanceof String text)) {
            return false;
        }
        String[] parts = text.split("\\.", -1);
        if (parts.length != 5 || !parts[1].isEmpty()) {
            return false;
        }
        try {
            Map<String, Object> header = JSON.readValue(Base64Url.decodeToString(parts[0]), Map.class);
            return header.get("alg") instanceof String && header.get("enc") instanceof String;
        } catch (RuntimeException e) {
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> readHeader(String jwe) {
        return JSON.readValue(Base64Url.decodeToString(jwe.split("\\.", -1)[0]), Map.class);
    }

    private static byte[] deriveSharedSecret(ECPrivateKey privateKey, ECPublicKey publicKey) {
        try {
            KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
            agreement.init(privateKey);
            agreement.doPhase(publicKey, true);
            return agreement.generateSecret();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("ECDH key agreement failed", e);
        }
    }

    private static byte[] aesGcm(int mode, byte[] cek, byte[] iv, String aadHeaderB64, byte[] input) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(aadHeaderB64.getBytes(StandardCharsets.US_ASCII));
            return cipher.doFinal(input);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM " + (mode == Cipher.ENCRYPT_MODE ? "encryption" : "decryption")
                    + " failed", e);
        }
    }
}
