package id.notabene.e2ee.config;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Everything configurable, bound from application.yml (and overridable by
 * environment variables such as VASP_A_CLIENT_SECRET).
 */
@ConfigurationProperties(prefix = "notabene")
public class NotabeneProperties {

    /** EU node by default; use https://api.us1.notabene.id for the US node. */
    private String apiBase = "https://api.eu1.notabene.id";

    private String authUrl = "https://auth.notabene.id/oauth/token";

    /** Defaults to apiBase when left blank. */
    private String audience = "";

    /** branch (one JWE per top-level IVMS101 branch) or field (one per leaf). */
    private String piiMode = "branch";

    /** Where keys/<vasp>.json live. Same format as the JavaScript project. */
    private String keyDir = "keys";

    /** DIDDoc key id fragment. Notabene resolves "#pii" first. */
    private String keyFragment = "pii";

    /** Skip jurisdictional validation of the presentation while experimenting. */
    private boolean skipValidation = true;

    private final Transfer transfer = new Transfer();
    private final Polling polling = new Polling();

    /** Logical name -> VASP. Any number of them; "send" names two of these. */
    private Map<String, Vasp> vasps = new LinkedHashMap<>();

    public static class Vasp {
        private String did;
        private String clientId;
        private String clientSecret;

        public String getDid() {
            return did;
        }

        public void setDid(String did) {
            this.did = did;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public boolean hasCredentials() {
            return clientId != null && !clientId.isBlank() && clientSecret != null && !clientSecret.isBlank();
        }
    }

    public static class Transfer {
        private String asset = "eip155:1/slip44:60";
        private String amount = "1.5";
        private String originatorAddress = "0x1111111111111111111111111111111111111111";
        private String beneficiaryAddress = "0x2222222222222222222222222222222222222222";

        public String getAsset() {
            return asset;
        }

        public void setAsset(String asset) {
            this.asset = asset;
        }

        public String getAmount() {
            return amount;
        }

        public void setAmount(String amount) {
            this.amount = amount;
        }

        public String getOriginatorAddress() {
            return originatorAddress;
        }

        public void setOriginatorAddress(String originatorAddress) {
            this.originatorAddress = originatorAddress;
        }

        public String getBeneficiaryAddress() {
            return beneficiaryAddress;
        }

        public void setBeneficiaryAddress(String beneficiaryAddress) {
            this.beneficiaryAddress = beneficiaryAddress;
        }
    }

    public static class Polling {
        private int defaultIntervalSeconds = 15;
        private int limit = 25;
        /** Notabene's list filter; "incoming" is what a beneficiary wants. */
        private String direction = "incoming";
        /** How many decrypted messages to keep per VASP for inspection. */
        private int historySize = 50;

        public int getDefaultIntervalSeconds() {
            return defaultIntervalSeconds;
        }

        public void setDefaultIntervalSeconds(int defaultIntervalSeconds) {
            this.defaultIntervalSeconds = defaultIntervalSeconds;
        }

        public int getLimit() {
            return limit;
        }

        public void setLimit(int limit) {
            this.limit = limit;
        }

        public String getDirection() {
            return direction;
        }

        public void setDirection(String direction) {
            this.direction = direction;
        }

        public int getHistorySize() {
            return historySize;
        }

        public void setHistorySize(int historySize) {
            this.historySize = historySize;
        }
    }

    public String getApiBase() {
        return apiBase;
    }

    public void setApiBase(String apiBase) {
        this.apiBase = apiBase;
    }

    public String getAuthUrl() {
        return authUrl;
    }

    public void setAuthUrl(String authUrl) {
        this.authUrl = authUrl;
    }

    public String getAudience() {
        return (audience == null || audience.isBlank()) ? apiBase : audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public String getPiiMode() {
        return piiMode;
    }

    public void setPiiMode(String piiMode) {
        this.piiMode = piiMode;
    }

    public String getKeyDir() {
        return keyDir;
    }

    public void setKeyDir(String keyDir) {
        this.keyDir = keyDir;
    }

    public String getKeyFragment() {
        return keyFragment;
    }

    public void setKeyFragment(String keyFragment) {
        this.keyFragment = keyFragment;
    }

    public boolean isSkipValidation() {
        return skipValidation;
    }

    public void setSkipValidation(boolean skipValidation) {
        this.skipValidation = skipValidation;
    }

    public Transfer getTransfer() {
        return transfer;
    }

    public Polling getPolling() {
        return polling;
    }

    public Map<String, Vasp> getVasps() {
        return vasps;
    }

    public void setVasps(Map<String, Vasp> vasps) {
        this.vasps = vasps;
    }

    /** Look a VASP up by its configured name, failing with the list of valid names. */
    public Vasp requireVasp(String name) {
        Vasp vasp = vasps.get(name);
        if (vasp == null) {
            throw new IllegalArgumentException(
                    "Unknown VASP \"" + name + "\". Configured: " + vasps.keySet());
        }
        if (vasp.getDid() == null || vasp.getDid().isBlank()) {
            throw new IllegalArgumentException("VASP \"" + name + "\" has no DID configured");
        }
        return vasp;
    }
}
