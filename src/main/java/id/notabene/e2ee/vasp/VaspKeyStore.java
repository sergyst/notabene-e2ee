package id.notabene.e2ee.vasp;

import id.notabene.e2ee.config.NotabeneProperties;
import id.notabene.e2ee.crypto.Base64Url;
import id.notabene.e2ee.crypto.Hex;
import id.notabene.e2ee.crypto.Jwk;
import id.notabene.e2ee.crypto.P256;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

/**
 * Loads each VASP's PII keypair from keys/&lt;name&gt;.json, generating one on
 * first use. The private half never leaves this process - that is what makes
 * the encryption end-to-end.
 */
@Component
public class VaspKeyStore {

    private static final Logger log = LoggerFactory.getLogger(VaspKeyStore.class);

    private final NotabeneProperties properties;
    private final ObjectMapper json;
    private final Map<String, VaspKeypair> cache = new ConcurrentHashMap<>();

    public VaspKeyStore(NotabeneProperties properties, ObjectMapper json) {
        this.properties = properties;
        this.json = json;
    }

    public VaspKeypair keypairFor(String vaspName) {
        return cache.computeIfAbsent(vaspName, this::loadOrCreate);
    }

    private VaspKeypair loadOrCreate(String vaspName) {
        NotabeneProperties.Vasp vasp = properties.requireVasp(vaspName);
        Path file = keyFile(vaspName);

        if (Files.exists(file)) {
            VaspKeypair loaded = read(vaspName, file);
            if (!loaded.did().equals(vasp.getDid())) {
                log.warn("{} key file {} was generated for DID {} but configuration says {}. "
                        + "Delete the file to regenerate, or fix the DID.",
                        vaspName, file, loaded.did(), vasp.getDid());
            }
            log.info("{}: loaded PII key {} from {}", vaspName, loaded.kid(), file);
            return loaded;
        }

        VaspKeypair generated = generate(vaspName, vasp.getDid());
        write(file, generated);
        log.info("{}: generated a new PII key {} and wrote {}", vaspName, generated.kid(), file);
        log.info("{}: publish this in the DIDDoc verificationMethod and keyAgreement -> {}",
                vaspName, json.writeValueAsString(generated.didDocEntry()));
        return generated;
    }

    public Path keyFile(String vaspName) {
        return Path.of(properties.getKeyDir(), vaspName + ".json");
    }

    /** Generate a fresh PII keypair plus everything needed to publish it. */
    public VaspKeypair generate(String vaspName, String did) {
        KeyPair pair = P256.generateKeyPair();
        ECPublicKey publicKey = (ECPublicKey) pair.getPublic();
        ECPrivateKey privateKey = (ECPrivateKey) pair.getPrivate();

        String kid = did + "#" + properties.getKeyFragment();
        String publicKeyHex = Hex.encode(P256.encodePoint(publicKey, true));

        return new VaspKeypair(
                vaspName,
                did,
                kid,
                Hex.encode(P256.toFixedLength(privateKey.getS())),
                publicKeyHex,
                Hex.encode(P256.encodePoint(publicKey, false)),
                P256.toJwk(publicKey, privateKey),
                P256.toJwk(publicKey),
                didDocEntryJwk(kid, did, P256.toJwk(publicKey)),
                didDocEntryHex(kid, did, publicKeyHex));
    }

    @SuppressWarnings("unchecked")
    private VaspKeypair read(String vaspName, Path file) {
        try {
            Map<String, Object> raw = json.readValue(Files.readString(file), Map.class);
            Jwk privateJwk = readPrivateJwk(file, raw);
            String did = (String) raw.get("did");
            String kid = (String) raw.get("kid");
            String publicKeyHex = (String) raw.get("publicKeyHex");
            // Rebuild the DIDDoc entries rather than trusting the file, so both
            // encodings always describe the key that is actually in it.
            return new VaspKeypair(
                    vaspName,
                    did,
                    kid,
                    (String) raw.get("privateKeyHex"),
                    publicKeyHex,
                    (String) raw.get("publicKeyHexUncompressed"),
                    privateJwk,
                    privateJwk.publicOnly(),
                    didDocEntryJwk(kid, did, privateJwk.publicOnly()),
                    didDocEntryHex(kid, did, publicKeyHex));
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read " + file, e);
        }
    }

    /**
     * The shape Notabene's current V2 recipe publishes. Their DIDDoc also needs
     * https://w3id.org/security/suites/ecdsa-2019/v1 in @context.
     */
    private static Map<String, Object> didDocEntryJwk(String kid, String did, Jwk publicJwk) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("id", kid);
        entry.put("type", "JsonWebKey2020");
        entry.put("controller", did);
        entry.put("publicKeyJwk", publicJwk.toPublicMap());
        return entry;
    }

    /** The older hex shape from their Key Management in DIDdocs page. */
    private static Map<String, Object> didDocEntryHex(String kid, String did, String publicKeyHex) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("id", kid);
        entry.put("type", "EcdsaSecp256r1VerificationKey2019");
        entry.put("controller", did);
        entry.put("publicKeyHex", publicKeyHex);
        return entry;
    }

    /**
     * Key files written here (and by the JavaScript project) carry privateJwk.
     * Fall back to rebuilding it from publicKeyHex + privateKeyHex, which is
     * enough because the public point is stored alongside the scalar.
     */
    @SuppressWarnings("unchecked")
    private Jwk readPrivateJwk(Path file, Map<String, Object> raw) {
        if (raw.get("privateJwk") instanceof Map<?, ?> jwkMap) {
            return Jwk.fromMap((Map<String, ?>) jwkMap);
        }
        String privateKeyHex = (String) raw.get("privateKeyHex");
        String publicKeyHex = (String) raw.get("publicKeyHex");
        if (privateKeyHex == null || publicKeyHex == null) {
            throw new IllegalStateException(file + " has neither privateJwk nor privateKeyHex + publicKeyHex. "
                    + "Delete it and let the application regenerate the key.");
        }
        Jwk pub = P256.hexToJwk(publicKeyHex);
        BigInteger s = new BigInteger(1, Hex.decode(privateKeyHex));
        return new Jwk(pub.kty(), pub.crv(), pub.x(), pub.y(), Base64Url.encode(P256.toFixedLength(s)));
    }

    private void write(Path file, VaspKeypair keypair) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("did", keypair.did());
        out.put("kid", keypair.kid());
        out.put("privateKeyHex", keypair.privateKeyHex());
        out.put("publicKeyHex", keypair.publicKeyHex());
        out.put("publicKeyHexUncompressed", keypair.publicKeyHexUncompressed());
        out.put("privateJwk", jwkMap(keypair.privateJwk()));
        out.put("publicJwk", jwkMap(keypair.publicJwk()));
        out.put("didDocEntry", keypair.didDocEntry());
        out.put("didDocEntryHexVariant", keypair.didDocEntryHexVariant());

        try {
            if (file.getParent() != null) {
                Files.createDirectories(file.getParent());
            }
            Files.writeString(file, json.writerWithDefaultPrettyPrinter().writeValueAsString(out) + "\n",
                    StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not write " + file, e);
        }
    }

    /** Ordered, and without a null "d" member on public keys. */
    private static Map<String, Object> jwkMap(Jwk jwk) {
        Map<String, Object> map = jwk.toPublicMap();
        if (jwk.isPrivate()) {
            map.put("d", jwk.d());
        }
        return map;
    }
}
