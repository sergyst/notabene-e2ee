package id.notabene.e2ee.crypto;

import java.math.BigInteger;

/**
 * Bitcoin-alphabet base58, only the decode half - Notabene publishes some keys
 * as publicKeyBase58 in a DIDDoc.
 */
public final class Base58 {

    private static final String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    private Base58() {
    }

    public static byte[] decode(String value) {
        BigInteger number = BigInteger.ZERO;
        for (char c : value.toCharArray()) {
            int digit = ALPHABET.indexOf(c);
            if (digit < 0) {
                throw new IllegalArgumentException("Invalid base58 character: " + c);
            }
            number = number.multiply(BigInteger.valueOf(58)).add(BigInteger.valueOf(digit));
        }

        byte[] magnitude = number.toByteArray();
        int offset = (magnitude.length > 1 && magnitude[0] == 0) ? 1 : 0;

        int leadingZeros = 0;
        while (leadingZeros < value.length() && value.charAt(leadingZeros) == '1') {
            leadingZeros++;
        }

        byte[] out = new byte[leadingZeros + magnitude.length - offset];
        System.arraycopy(magnitude, offset, out, leadingZeros, magnitude.length - offset);
        return out;
    }
}
