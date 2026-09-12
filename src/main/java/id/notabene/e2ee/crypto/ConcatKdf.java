package id.notabene.e2ee.crypto;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * NIST SP 800-56A Concat KDF as profiled by RFC 7518 section 4.6.2.
 *
 * A single SHA-256 round is enough for a 256-bit key. Notabene's interop
 * profile spells out the exact input construction this mirrors:
 *   AlgorithmID = len("A256GCM") || "A256GCM"
 *   PartyUInfo  = len(apu) || apu, or four zero bytes when absent
 *   PartyVInfo  = len(apv) || apv, or four zero bytes when absent
 *   SuppPubInfo = keydatalen in bits, 32-bit big endian
 */
public final class ConcatKdf {

    private ConcatKdf() {
    }

    public static byte[] deriveKey(byte[] sharedSecret, String algorithmId, byte[] apu, byte[] apv, int keyDataLenBits) {
        ByteArrayOutputStream input = new ByteArrayOutputStream();
        writeInt(input, 1); // round counter
        input.writeBytes(sharedSecret);
        input.writeBytes(lengthPrefixed(algorithmId.getBytes(StandardCharsets.UTF_8)));
        input.writeBytes(lengthPrefixed(apu == null ? new byte[0] : apu));
        input.writeBytes(lengthPrefixed(apv == null ? new byte[0] : apv));
        writeInt(input, keyDataLenBits);

        byte[] digest = sha256(input.toByteArray());
        int keyLen = keyDataLenBits / 8;
        if (digest.length == keyLen) {
            return digest;
        }
        byte[] key = new byte[keyLen];
        System.arraycopy(digest, 0, key, 0, keyLen);
        return key;
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required but unavailable", e);
        }
    }

    public static byte[] sha256(String utf8) {
        return sha256(utf8.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] lengthPrefixed(byte[] bytes) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeInt(out, bytes.length);
        out.writeBytes(bytes);
        return out.toByteArray();
    }

    private static void writeInt(ByteArrayOutputStream out, int value) {
        out.write((value >>> 24) & 0xff);
        out.write((value >>> 16) & 0xff);
        out.write((value >>> 8) & 0xff);
        out.write(value & 0xff);
    }
}
