package id.notabene.e2ee.service;

import id.notabene.e2ee.config.NotabeneProperties;
import id.notabene.e2ee.crypto.EcdhEsJwe;
import id.notabene.e2ee.ivms.Channel;
import id.notabene.e2ee.ivms.IvmsCrypto;
import id.notabene.e2ee.notabene.NotabeneApiException;
import id.notabene.e2ee.notabene.NotabeneClient;
import id.notabene.e2ee.vasp.LocalLedger;
import id.notabene.e2ee.vasp.VaspKeyStore;
import id.notabene.e2ee.vasp.VaspKeypair;
import id.notabene.e2ee.web.dto.TransferDetail;
import id.notabene.e2ee.web.dto.TransferSummary;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/** Reading transfers, from Notabene or from the local ledger, for one VASP or all of them. */
@Service
public class TransferService {

    private static final Logger log = LoggerFactory.getLogger(TransferService.class);

    private final NotabeneProperties properties;
    private final NotabeneClient client;
    private final IvmsCrypto ivmsCrypto;
    private final VaspKeyStore keyStore;
    private final LocalLedger ledger;

    public TransferService(NotabeneProperties properties, NotabeneClient client, IvmsCrypto ivmsCrypto,
            VaspKeyStore keyStore, LocalLedger ledger) {
        this.properties = properties;
        this.client = client;
        this.ivmsCrypto = ivmsCrypto;
        this.keyStore = keyStore;
        this.ledger = ledger;
    }

    /** Names to query: the ones asked for, or every configured VASP. */
    public List<String> resolveVasps(List<String> requested) {
        if (requested == null || requested.isEmpty()) {
            return List.copyOf(properties.getVasps().keySet());
        }
        requested.forEach(properties::requireVasp);
        return requested;
    }

    public List<TransferSummary> list(List<String> vaspNames, Channel channel, String direction, int limit) {
        List<TransferSummary> out = new ArrayList<>();
        for (String vaspName : resolveVasps(vaspNames)) {
            out.addAll(channel == Channel.LOCAL
                    ? listLocal(vaspName)
                    : listNotabene(vaspName, direction, limit));
        }
        // Newest first across every VASP, so the combined view reads chronologically.
        out.sort(Comparator.comparing(
                (TransferSummary s) -> s.createdAt() == null ? "" : s.createdAt()).reversed());
        return out;
    }

    private List<TransferSummary> listNotabene(String vaspName, String direction, int limit) {
        NotabeneProperties.Vasp vasp = properties.requireVasp(vaspName);
        List<TransferSummary> out = new ArrayList<>();
        for (Map<String, Object> raw : client.listTransfers(vasp, direction, limit)) {
            out.add(toSummary(vaspName, vasp.getDid(), Channel.NOTABENE, raw));
        }
        return out;
    }

    private List<TransferSummary> listLocal(String vaspName) {
        List<TransferSummary> out = new ArrayList<>();
        for (LocalLedger.Entry entry : ledger.forVasp(vaspName)) {
            boolean outgoing = entry.fromVasp().equals(vaspName);
            out.add(new TransferSummary(
                    entry.id(),
                    vaspName,
                    properties.requireVasp(vaspName).getDid(),
                    Channel.LOCAL.lower(),
                    outgoing ? "OUTGOING" : "INCOMING",
                    "PRESENTED",
                    entry.asset(),
                    entry.amount(),
                    entry.createdAt().toString(),
                    entry.originatorDid(),
                    entry.beneficiaryDid(),
                    outgoing ? entry.toVasp() : entry.fromVasp(),
                    null,
                    Map.of("mode", entry.mode(), "recipientKid", entry.recipientKid())));
        }
        return out;
    }

    public TransferDetail detail(String vaspName, String transferId, Channel channel) {
        NotabeneProperties.Vasp vasp = properties.requireVasp(vaspName);
        VaspKeypair keypair = keyStore.keypairFor(vaspName);

        TransferSummary summary;
        Object encrypted;

        if (channel == Channel.LOCAL) {
            LocalLedger.Entry entry = ledger.get(transferId);
            if (entry == null) {
                throw new IllegalArgumentException("No local transfer " + transferId);
            }
            summary = listLocal(vaspName).stream()
                    .filter(s -> s.id().equals(transferId))
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException(
                            vaspName + " is not a party to local transfer " + transferId));
            encrypted = entry.encryptedIvms101();
        } else {
            Map<String, Object> full;
            try {
                // decrypt=false: we want the ciphertext, not Notabene's copy.
                full = client.getTransfer(vasp, transferId, false);
            } catch (NotabeneApiException e) {
                throw new IllegalArgumentException(
                        "Could not load transfer " + transferId + " as " + vaspName + ": " + e.getMessage());
            }
            Object body = full.get("transfer") instanceof Map<?, ?> m ? m : full;
            @SuppressWarnings("unchecked")
            Map<String, Object> raw = (Map<String, Object>) body;
            summary = toSummary(vaspName, vasp.getDid(), Channel.NOTABENE, raw);
            encrypted = ivmsCrypto.findIvms(full);
        }

        if (encrypted == null) {
            return new TransferDetail(summary, false, null, null, null, 0, null, List.of());
        }

        try {
            IvmsCrypto.DecryptResult result = ivmsCrypto.decrypt(
                    encrypted, keypair.privateJwk(), null, null);
            List<TransferDetail.FieldValue> fields = ivmsCrypto.flattenLeaves(result.payload()).stream()
                    .map(leaf -> new TransferDetail.FieldValue(
                            leaf.path().replaceFirst("^\\$\\.?", ""), leaf.value()))
                    .toList();
            Map<String, Object> header = result.parts().isEmpty()
                    ? null
                    : EcdhEsJwe.readHeader(result.parts().get(0).jwe());
            log.info("{}: decrypted {} JWE(s) from transfer {}", vaspName, result.parts().size(), transferId);
            return new TransferDetail(summary, true, encrypted, result.payload(), null,
                    result.parts().size(), header, fields);
        } catch (RuntimeException e) {
            log.warn("{}: could not decrypt transfer {}: {}", vaspName, transferId, e.getMessage());
            return new TransferDetail(summary, true, encrypted, null, e.getMessage(), 0, null, List.of());
        }
    }

    private static TransferSummary toSummary(String vaspName, String vaspDid, Channel channel,
            Map<String, Object> raw) {
        String direction = str(raw.get("direction"));
        String originator = partyId(raw.get("originator"));
        String beneficiary = partyId(raw.get("beneficiary"));
        String counterparty = "OUTGOING".equalsIgnoreCase(direction) ? beneficiary : originator;

        return new TransferSummary(
                str(raw.getOrDefault("id", raw.get("@id"))),
                vaspName,
                vaspDid,
                channel.lower(),
                direction,
                str(raw.get("status")),
                str(raw.get("asset")),
                str(raw.get("amount")),
                str(raw.get("createdAt")),
                originator,
                beneficiary,
                counterparty,
                str(raw.get("ref")),
                raw);
    }

    private static String partyId(Object party) {
        if (party instanceof Map<?, ?> map) {
            Object id = map.get("@id");
            return id == null ? null : id.toString();
        }
        return party == null ? null : party.toString();
    }

    private static String str(Object value) {
        return value == null ? null : value.toString();
    }
}
