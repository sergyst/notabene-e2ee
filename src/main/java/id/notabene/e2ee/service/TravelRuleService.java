package id.notabene.e2ee.service;

import id.notabene.e2ee.config.NotabeneProperties;
import id.notabene.e2ee.crypto.EcdhEsJwe;
import id.notabene.e2ee.crypto.Jwk;
import id.notabene.e2ee.crypto.P256;
import id.notabene.e2ee.ivms.IvmsCrypto;
import id.notabene.e2ee.ivms.PiiMode;
import id.notabene.e2ee.ivms.SamplePii;
import id.notabene.e2ee.notabene.NotabeneClient;
import id.notabene.e2ee.notabene.TransferBodies;
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

    public TravelRuleService(NotabeneProperties properties, NotabeneClient client, IvmsCrypto ivmsCrypto,
            SamplePii samplePii) {
        this.properties = properties;
        this.client = client;
        this.ivmsCrypto = ivmsCrypto;
        this.samplePii = samplePii;
    }

    public SendResponse send(SendRequest request) {
        NotabeneProperties.Vasp sender    = properties.requireVasp(request.from());
        NotabeneProperties.Vasp recipient = properties.requireVasp(request.to());
        PiiMode mode = request.mode() == null ? PiiMode.from(properties.getPiiMode()) : PiiMode.from(request.mode());

        // 1 - the counterparty's published PII key.
        Map<String, Object> keyResponse = client.getEntityPublicKeys(sender, recipient.getDid());
        Map<String, Object> encryptionKey = asMap(keyResponse.get("encryptionKey"), keyResponse);
        Jwk recipientJwk = toJwk(encryptionKey);
        String recipientKid = encryptionKey.get("id") instanceof String id ? id
                : recipient.getDid() + "#" + properties.getKeyFragment();

        String warning = null;
        if (!recipientKid.endsWith("#" + properties.getKeyFragment())) {
            warning = "Recipient key id \"" + recipientKid + "\" does not end in \"#" + properties.getKeyFragment()
                    + "\" - " + request.to() + " is probably still on Notabene-managed encryption. Publish the "
                    + "\"#pii\" key from GET /api/vasps in its DIDDoc for true end-to-end encryption.";
            log.warn(warning);
        }
        log.info("recipient key {} ({})", recipientKid, encryptionKey.get("type"));

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
        Map<String, Object> pii = request.pii() == null || request.pii().isEmpty() ? samplePii.get() : request.pii();
        IvmsCrypto.EncryptResult encrypted = ivmsCrypto.encrypt(
                pii, mode, recipientJwk, recipientKid, sender.getDid());
        Map<String, Object> header = EcdhEsJwe.readHeader(encrypted.parts().get(0).jwe());
        log.info("encrypted {} JWE(s) [{}] alg={} enc={} kid={}",
                encrypted.parts().size(), mode.lower(), header.get("alg"), header.get("enc"), header.get("kid"));

        // 4 - present the ciphertext.
        Map<String, Object> presented = client.presentPii(sender, transferId, encrypted.payload(), request.policyId());
        log.info("Notabene accepted the presentation for {}: {}", transferId, presented);

        List<String> parts = encrypted.parts().stream().map(p -> p.path().replaceFirst("^\\$\\.?", "")).toList();
        return new SendResponse(transferId, request.from(), request.to(), recipientKid, mode.lower(),
                encrypted.parts().size(), parts, encrypted.payload(), presented, warning);
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

    private static String extractTransferId(Map<String, Object> created) {
        Object transfer = created.get("transfer");
        if (transfer instanceof Map<?, ?> map && map.get("id") != null) {
            return map.get("id").toString();
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
