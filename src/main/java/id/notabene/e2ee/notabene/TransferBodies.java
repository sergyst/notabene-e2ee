package id.notabene.e2ee.notabene;

import id.notabene.e2ee.config.NotabeneProperties;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Builds the transfer body for a hosted-to-hosted VASP transfer. */
public final class TransferBodies {

    private TransferBodies() {
    }

    public static Map<String, Object> hostedToHosted(NotabeneProperties.Transfer transfer, String originatorVaspDid,
            String beneficiaryVaspDid, String originatorId, String beneficiaryId) {

        List<Map<String, Object>> agents = new ArrayList<>();
        agents.add(agent("did:pkh:eip155:1:" + transfer.getOriginatorAddress(), originatorVaspDid, "SourceAddress"));
        agents.add(agent(originatorVaspDid, originatorId, "VASP"));
        agents.add(agent(beneficiaryVaspDid, beneficiaryId, "VASP"));
        agents.add(agent("did:pkh:eip155:1:" + transfer.getBeneficiaryAddress(), beneficiaryVaspDid,
                "SettlementAddress"));

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("originator", Map.of("@id", originatorId));
        body.put("beneficiary", Map.of("@id", beneficiaryId));
        body.put("asset", transfer.getAsset());
        body.put("amount", transfer.getAmount());
        body.put("agents", agents);
        body.put("ref", "e2ee-demo-" + System.currentTimeMillis());
        return body;
    }

    private static Map<String, Object> agent(String id, String forParty, String role) {
        Map<String, Object> agent = new LinkedHashMap<>();
        agent.put("@id", id);
        agent.put("for", forParty);
        agent.put("role", role);
        return agent;
    }
}
