package id.notabene.e2ee.notabene;

import id.notabene.e2ee.config.NotabeneProperties;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/** Builds the POST /api/v1/transfers body for a withdrawal to another VASP's address. */
public final class TransferBodies {

    private TransferBodies() {
    }

    /**
     * @param originatorId       IRI of the sending customer (required for a withdrawal)
     * @param beneficiaryDid     the institution that owns the settlement address
     * @param settlementAddress  where the funds go; bare or CAIP-10, blank for the configured sample
     */
    public static Map<String, Object> withdrawal(NotabeneProperties.Transfer transfer, String originatorId,
            String beneficiaryDid, String settlementAddress) {

        String settlement = Addresses.toCaip10((settlementAddress == null || settlementAddress.isBlank())
                ? transfer.getBeneficiaryAddress()
                : settlementAddress);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ref", UUID.randomUUID().toString());
        body.put("asset", transfer.getAsset());
        body.put("amount", transfer.getAmount());
        body.put("originator_id", originatorId);
        body.put("source_address", Addresses.toCaip10(transfer.getOriginatorAddress()));
        body.put("settlement_address", settlement);
        body.put("beneficiary_entity_did", beneficiaryDid);
        return body;
    }
}
