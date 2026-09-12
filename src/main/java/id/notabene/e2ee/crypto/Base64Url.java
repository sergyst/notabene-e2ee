package id.notabene.e2ee.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** base64url without padding, as JOSE uses it everywhere. */
public final class Base64Url {

    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private Base64Url() {
    }

    public static String encode(byte[] bytes) {
        return ENCODER.encodeToString(bytes);
    }

    public static String encode(String utf8) {
        return encode(utf8.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] decode(String value) {
        return DECODER.decode(value);
    }

    public static String decodeToString(String value) {
        return new String(decode(value), StandardCharsets.UTF_8);
    }
}
