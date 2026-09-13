package id.notabene.e2ee.service;

import id.notabene.e2ee.config.NotabeneProperties;
import id.notabene.e2ee.crypto.EcdhEsJwe;
import id.notabene.e2ee.crypto.Jwk;
import id.notabene.e2ee.crypto.P256;
import id.notabene.e2ee.ivms.Channel;
import id.notabene.e2ee.ivms.IvmsCrypto;
import id.notabene.e2ee.ivms.PiiMode;
import id.notabene.e2ee.ivms.SamplePii;
import id.notabene.e2ee.notabene.NotabeneClient;
import id.notabene.e2ee.notabene.TransferBodies;
import id.notabene.e2ee.vasp.LocalLedger;
import id.notabene.e2ee.vasp.VaspKeyStore;
import java.time.Instant;
import java.util.UUID;
import id.notabene.e2ee.web.dto.RecipientKey;
import id.notabene.e2ee.web.dto.SendRequest;
import id.notabene.e2ee.web.dto.SendResponse;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * vaspA creates a transfer, encrypts the IVMS101 PII for vaspB, and presents
 * it. Notabene only ever sees ciphertext - the plaintext never leaves this
 * process.
 */
@Service
public class TravelRuleService {

    private static final Logger log = LoggerFactory.getLogger(TravelRuleService.class);

    private final NotabeneProperties properties;
    private final NotabeneClient client;
    private final IvmsCrypto ivmsCrypto;
    private final SamplePii samplePii;
    private final VaspKeyStore keyStore;
    private final LocalLedger ledger;

    public TravelRuleService(NotabeneProperties properties, NotabeneClient client, IvmsCrypto ivmsCrypto,
            SamplePii samplePii, VaspKeyStore keyStore, LocalLedger ledger) {
        this.properties = properties;
        this.client = client;
        this.ivmsCrypto = ivmsCrypto;
        this.samplePii = samplePii;
        this.keyStore = keyStore;
        this.ledger = ledger;
    }

    public SendResponse send(SendRequest request) {
        NotabeneProperties.Vasp sender    = properties.requireVasp(request.from());
        NotabeneProperties.Vasp recipient = properties.requireVasp(request.to());
        PiiMode mode = request.mode() == null ? PiiMode.from(properties.getPiiMode()) : PiiMode.from(request.mode());
        Channel channel = Channel.from(request.channel());
        Map<String, Object> pii = request.pii() == null || request.pii().isEmpty() ? samplePii.get() : request.pii();

        if (channel == Channel.LOCAL) {
            return sendLocal(request, sender, recipient, mode, pii);
        }

        // 1 - the key to encrypt to.
        ResolvedKey key = resolveRecipientKey(request, sender, recipient);
        Jwk recipientJwk = key.jwk();
        String recipientKid = key.kid();
        String warning = key.warning();
        log.info("recipient key {} (source: {})", recipientKid, key.source());

        // 2 - the transfer.
        String transferId = request.transferId();
        if (transferId == null || transferId.isBlank()) {
            Map<String, Object> body = TransferBodies.hostedToHosted(
                    properties.getTransfer(),
                    sender.getDid(),
                    recipient.getDid(),
                    orDefault(request.originatorId(), sender.getDid() + ":customer:john-doe"),
                    orDefault(request.beneficiaryId(), recipient.getDid() + ":customer:jane-smith"));
            Map<String, Object> created = client.createTransfer(sender, body);
            transferId = extractTransferId(created);
            log.info("created transfer {}", transferId);
        } else {
            log.info("reusing transfer {}", transferId);
        }

        // 3 - encrypt with our own code, before any further network call.
        IvmsCrypto.EncryptResult encrypted = ivmsCrypto.encrypt(
                pii, mode, recipientJwk, recipientKid, sender.getDid());
        Map<String, Object> header = EcdhEsJwe.readHeader(encrypted.parts().get(0).jwe());
        log.info("encrypted {} JWE(s) [{}] alg={} enc={} kid={}",
                encrypted.parts().size(), mode.lower(), header.get("alg"), header.get("enc"), header.get("kid"));

        // 4 - present the ciphertext.
        Map<String, Object> presented = client.presentPii(sender, transferId, encrypted.payload(), request.policyId());
        log.info("Notabene accepted the presentation for {}: {}", transferId, presented);

        List<String> parts = encrypted.parts().stream().map(p -> p.path().replaceFirst("^\\$\\.?", "")).toList();
        return new SendResponse(transferId, request.from(), request.to(), recipientKid, key.source(),
                mode.lower(), channel.lower(), encrypted.parts().size(), parts, encrypted.payload(),
                presented, warning);
    }

    private record ResolvedKey(Jwk jwk, String kid, String source, String warning) {
    }

    /**
     * Where the recipient's public key comes from. Notabene's directory by
     * default; this server's own keystore or a key supplied in the request when
     * that lookup cannot answer - a did:web that does not resolve makes
     * /public-keys return NO_ENCRYPTION_KEYS even though the hosted DID document
     * has a perfectly good key in it.
     */
    private ResolvedKey resolveRecipientKey(SendRequest request, NotabeneProperties.Vasp sender,
            NotabeneProperties.Vasp recipient) {

        RecipientKey requested = request.recipientKey();
        String source = requested == null || requested.source() == null || requested.source().isBlank()
                ? (requested != null && requested.hasExplicitMaterial() ? "explicit" : "notabene")
                : requested.source().trim().toLowerCase();
        String defaultKid = recipient.getDid() + "#" + properties.getKeyFragment();

        switch (source) {
            case "local" -> {
                var keys = keyStore.keypairFor(request.to());
                String kid = requested != null && requested.kid() != null && !requested.kid().isBlank()
                        ? requested.kid()
                        : keys.kid();
                return new ResolvedKey(keys.publicJwk(), kid, "local",
                        request.to() + " must hold the matching private key (" + keyStore.keyFile(request.to())
                                + ") to read this, and its public half must be published for anyone else to.");
            }
            case "explicit" -> {
                if (requested == null || !requested.hasExplicitMaterial()) {
                    throw new IllegalArgumentException(
                            "recipientKey.source is \"explicit\" but no publicKeyHex or publicKeyJwk was given");
                }
                Jwk jwk = requested.publicKeyJwk() != null && !requested.publicKeyJwk().isEmpty()
                        ? Jwk.fromMap(requested.publicKeyJwk())
                        : P256.hexToJwk(requested.publicKeyHex());
                String kid = requested.kid() != null && !requested.kid().isBlank() ? requested.kid() : defaultKid;
                String warning = (requested.kid() == null || requested.kid().isBlank())
                        ? "No kid given, so apv was bound to \"" + kid + "\". The recipient must expect that exact "
                                + "key id or its apv check will reject the message."
                        : null;
                return new ResolvedKey(jwk, kid, "explicit", warning);
            }
            case "notabene" -> {
                Map<String, Object> keyResponse = client.getEntityPublicKeys(sender, recipient.getDid());
                Map<String, Object> encryptionKey = asMap(keyResponse.get("encryptionKey"), keyResponse);
                Jwk jwk = toJwk(encryptionKey);
                String kid = encryptionKey.get("id") instanceof String id ? id : defaultKid;

                String warning = null;
                if (kid.endsWith("#notabene-pii")) {
                    warning = "Encrypting to \"" + kid + "\", which is Notabene's own key - they hold the private "
                            + "half and can read this PII. That is their hybrid model, not end-to-end. Publish your "
                            + "own \"#" + properties.getKeyFragment() + "\" key, or send recipientKey explicitly.";
                } else if (!kid.endsWith("#" + properties.getKeyFragment())) {
                    warning = "Recipient key id \"" + kid + "\" does not end in \"#" + properties.getKeyFragment()
                            + "\" - " + request.to() + " may still be on Notabene-managed encryption.";
                }
                if (warning != null) {
                    log.warn(warning);
                }
                return new ResolvedKey(jwk, kid, "notabene", warning);
            }
            default -> throw new IllegalArgumentException(
                    "Unknown recipientKey.source: \"" + source + "\". Use notabene, local or explicit.");
        }
    }

    /**
     * The same encryption, stored on this server instead of Notabene. Useful
     * before your "#pii" key is published in the DIDDoc, which Notabene needs
     * before it will hand out a counterparty key or accept a presentation.
     */
    private SendResponse sendLocal(SendRequest request, NotabeneProperties.Vasp sender,
            NotabeneProperties.Vasp recipient, PiiMode mode, Map<String, Object> pii) {

        var recipientKeys = keyStore.keypairFor(request.to());
        IvmsCrypto.EncryptResult encrypted = ivmsCrypto.encrypt(
                pii, mode, recipientKeys.publicJwk(), recipientKeys.kid(), sender.getDid());

        String transferId = (request.transferId() == null || request.transferId().isBlank())
                ? UUID.randomUUID().toString()
                : request.transferId();

        ledger.add(new LocalLedger.Entry(
                transferId,
                request.from(),
                request.to(),
                sender.getDid(),
                recipient.getDid(),
                properties.getTransfer().getAsset(),
                properties.getTransfer().getAmount(),
                mode.lower(),
                recipientKeys.kid(),
                Instant.now(),
                encrypted.payload()));

        log.info("local: {} -> {} stored transfer {} as {} JWE(s) [{}], encrypted to {}",
                request.from(), request.to(), transferId, encrypted.parts().size(), mode.lower(),
                recipientKeys.kid());

        List<String> parts = encrypted.parts().stream().map(p -> p.path().replaceFirst("^\\$\\.?", "")).toList();
        return new SendResponse(transferId, request.from(), request.to(), recipientKeys.kid(), "local",
                mode.lower(), Channel.LOCAL.lower(), encrypted.parts().size(), parts, encrypted.payload(),
                Map.of("message", "Stored in the local ledger - Notabene was not contacted"), null);
    }

    // ---------------------------------------------------------------- helpers

    /**
     * Normalise whatever /entities/:did/public-keys gives us into a JWK we can
     * run ECDH against.
     */
    private Jwk toJwk(Map<String, Object> encryptionKey) {
        if (encryptionKey.get("publicKeyJwk") instanceof Map<?, ?> jwkMap) {
            @SuppressWarnings("unchecked")
            Map<String, ?> typed = (Map<String, ?>) jwkMap;
            return Jwk.fromMap(typed);
        }
        if (encryptionKey.get("publicKeyHex") instanceof String hex) {
            return P256.hexToJwk(hex);
        }
        if (encryptionKey.get("publicKeyBase58") instanceof String base58) {
            String type = String.valueOf(encryptionKey.get("type"));
            if (type.startsWith("X25519")) {
                throw new IllegalStateException("Key " + encryptionKey.get("id") + " is X25519 (" + type
                        + "), not P-256. That is a Notabene-managed key - publish your own \"#pii\" "
                        + "EcdsaSecp256r1VerificationKey2019 in the DIDDoc and turn off Notabene-managed "
                        + "encryption in the Dashboard.");
            }
            return P256.base58ToJwk(base58);
        }
        throw new IllegalStateException("Unsupported encryption key format: " + encryptionKey);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value, Map<String, Object> fallback) {
        return value instanceof Map<?, ?> map ? (Map<String, Object>) map : fallback;
    }

    /** Notabene returns the id as "@id" inside "transfer"; other shapes appear in their docs. */
    private static String extractTransferId(Map<String, Object> created) {
        if (created.get("transfer") instanceof Map<?, ?> transfer) {
            for (String key : List.of("id", "@id", "transferId")) {
                if (transfer.get(key) != null) {
                    return transfer.get(key).toString();
                }
            }
        }
        for (String key : List.of("id", "@id", "transferId")) {
            if (created.get(key) != null) {
                return created.get(key).toString();
            }
        }
        throw new IllegalStateException("Could not find a transfer id in the create response: " + created);
    }

    private static String orDefault(String value, String fallback) {
        return (value == null || value.isBlank()) ? fallback : value;
    }
}
