package id.notabene.e2ee.crypto;

import java.util.HexFormat;

public final class Hex {

    private static final HexFormat FORMAT = HexFormat.of();

    private Hex() {
    }

    public static String encode(byte[] bytes) {
        return FORMAT.formatHex(bytes);
    }

    public static byte[] decode(String hex) {
        String cleaned = hex.startsWith("0x") ? hex.substring(2) : hex;
        return FORMAT.parseHex(cleaned);
    }
}
