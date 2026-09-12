package id.notabene.e2ee.crypto;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;

/**
 * P-256 (secp256r1) key handling on plain JCA - no BouncyCastle, no Nimbus.
 *
 * Notabene expects the public half in your DIDDoc as a key agreement entry
 * whose id ends in "#pii":
 * https://devx.notabene.id/docs/key-management-in-diddocs
 */
public final class P256 {

    private static final int COORD_BYTES = 32;
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final ECParameterSpec PARAMS = resolveParams();
    private static final BigInteger P = ((ECFieldFp) PARAMS.getCurve().getField()).getP();

    private P256() {
    }

    private static ECParameterSpec resolveParams() {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("P-256 is required but unavailable", e);
        }
    }

    public static ECParameterSpec params() {
        return PARAMS;
    }

    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Could not generate a P-256 key pair", e);
        }
    }

    // ---------------------------------------------------------------- JWK <-> JCA

    public static ECPublicKey toPublicKey(Jwk jwk) {
        ECPoint point = new ECPoint(
                new BigInteger(1, Base64Url.decode(jwk.x())),
                new BigInteger(1, Base64Url.decode(jwk.y())));
        assertOnCurve(point);
        try {
            return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, PARAMS));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid P-256 public JWK", e);
        }
    }

    public static ECPrivateKey toPrivateKey(Jwk jwk) {
        if (!jwk.isPrivate()) {
            throw new IllegalArgumentException("JWK has no private component (d)");
        }
        BigInteger s = new BigInteger(1, Base64Url.decode(jwk.d()));
        try {
            return (ECPrivateKey) KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(s, PARAMS));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid P-256 private JWK", e);
        }
    }

    public static Jwk toJwk(ECPublicKey key) {
        ECPoint w = key.getW();
        return Jwk.publicKey(
                Base64Url.encode(toFixedLength(w.getAffineX())),
                Base64Url.encode(toFixedLength(w.getAffineY())));
    }

    public static Jwk toJwk(ECPublicKey publicKey, ECPrivateKey privateKey) {
        Jwk pub = toJwk(publicKey);
        return new Jwk(pub.kty(), pub.crv(), pub.x(), pub.y(),
                Base64Url.encode(toFixedLength(privateKey.getS())));
    }

    // ---------------------------------------------------------------- SEC1 points

    /** Compressed (0x02/0x03) or uncompressed (0x04) SEC1 point to a public JWK. */
    public static Jwk pointToJwk(byte[] encoded) {
        ECPoint point = decodePoint(encoded);
        return Jwk.publicKey(
                Base64Url.encode(toFixedLength(point.getAffineX())),
                Base64Url.encode(toFixedLength(point.getAffineY())));
    }

    public static Jwk hexToJwk(String hex) {
        return pointToJwk(Hex.decode(hex));
    }

    public static Jwk base58ToJwk(String base58) {
        return pointToJwk(Base58.decode(base58));
    }

    /** SEC1 encoding of a public key: 0x04||X||Y, or 0x02/0x03||X when compressed. */
    public static byte[] encodePoint(ECPublicKey key, boolean compressed) {
        byte[] x = toFixedLength(key.getW().getAffineX());
        if (!compressed) {
            byte[] out = new byte[1 + 2 * COORD_BYTES];
            out[0] = 0x04;
            System.arraycopy(x, 0, out, 1, COORD_BYTES);
            System.arraycopy(toFixedLength(key.getW().getAffineY()), 0, out, 1 + COORD_BYTES, COORD_BYTES);
            return out;
        }
        byte[] out = new byte[1 + COORD_BYTES];
        out[0] = (byte) (key.getW().getAffineY().testBit(0) ? 0x03 : 0x02);
        System.arraycopy(x, 0, out, 1, COORD_BYTES);
        return out;
    }

    private static ECPoint decodePoint(byte[] encoded) {
        if (encoded.length == 0) {
            throw new IllegalArgumentException("Empty EC point");
        }
        ECPoint point = switch (encoded[0]) {
            case 0x04 -> {
                if (encoded.length != 1 + 2 * COORD_BYTES) {
                    throw new IllegalArgumentException("Uncompressed P-256 point must be 65 bytes, got " + encoded.length);
                }
                yield new ECPoint(
                        new BigInteger(1, slice(encoded, 1, COORD_BYTES)),
                        new BigInteger(1, slice(encoded, 1 + COORD_BYTES, COORD_BYTES)));
            }
            case 0x02, 0x03 -> {
                if (encoded.length != 1 + COORD_BYTES) {
                    throw new IllegalArgumentException("Compressed P-256 point must be 33 bytes, got " + encoded.length);
                }
                yield decompress(new BigInteger(1, slice(encoded, 1, COORD_BYTES)), encoded[0] == 0x03);
            }
            default -> throw new IllegalArgumentException(
                    "Unsupported EC point encoding: 0x" + Integer.toHexString(encoded[0] & 0xff));
        };
        assertOnCurve(point);
        return point;
    }

    /**
     * Recover Y from X. P-256's field prime is congruent to 3 mod 4, so the
     * square root is a single modular exponentiation by (p+1)/4.
     */
    private static ECPoint decompress(BigInteger x, boolean yIsOdd) {
        BigInteger a = PARAMS.getCurve().getA();
        BigInteger b = PARAMS.getCurve().getB();
        BigInteger alpha = x.modPow(THREE, P).add(a.multiply(x)).add(b).mod(P);
        BigInteger y = alpha.modPow(P.add(BigInteger.ONE).shiftRight(2), P);
        if (!y.modPow(BigInteger.TWO, P).equals(alpha)) {
            throw new IllegalArgumentException("Point is not on the P-256 curve (no square root for X)");
        }
        if (y.testBit(0) != yIsOdd) {
            y = P.subtract(y);
        }
        return new ECPoint(x, y);
    }

    /**
     * Reject points that are not on the curve. Notabene's decryption workflow
     * calls this out explicitly for the ephemeral key in a JWE header, since
     * accepting an off-curve point leaks private key bits.
     */
    public static void assertOnCurve(ECPoint point) {
        if (point.equals(ECPoint.POINT_INFINITY)) {
            throw new IllegalArgumentException("EC point is the point at infinity");
        }
        BigInteger x = point.getAffineX();
        BigInteger y = point.getAffineY();
        if (x.signum() < 0 || x.compareTo(P) >= 0 || y.signum() < 0 || y.compareTo(P) >= 0) {
            throw new IllegalArgumentException("EC point coordinates are outside the field");
        }
        BigInteger left = y.modPow(BigInteger.TWO, P);
        BigInteger right = x.modPow(THREE, P)
                .add(PARAMS.getCurve().getA().multiply(x))
                .add(PARAMS.getCurve().getB())
                .mod(P);
        if (!left.equals(right)) {
            throw new IllegalArgumentException("EC point is not on the P-256 curve");
        }
    }

    /** Left-pad to 32 bytes and drop BigInteger's sign byte. */
    public static byte[] toFixedLength(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == COORD_BYTES) {
            return bytes;
        }
        byte[] out = new byte[COORD_BYTES];
        if (bytes.length > COORD_BYTES) {
            System.arraycopy(bytes, bytes.length - COORD_BYTES, out, 0, COORD_BYTES);
        } else {
            System.arraycopy(bytes, 0, out, COORD_BYTES - bytes.length, bytes.length);
        }
        return out;
    }

    private static byte[] slice(byte[] source, int from, int length) {
        byte[] out = new byte[length];
        System.arraycopy(source, from, out, 0, length);
        return out;
    }
}
