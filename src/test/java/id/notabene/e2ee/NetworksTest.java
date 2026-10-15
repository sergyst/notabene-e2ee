package id.notabene.e2ee;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import id.notabene.e2ee.notabene.Networks;
import org.junit.jupiter.api.Test;

class NetworksTest {

    private static final String ADDR = "0x56F55666578B9adb170aEb77eCc8bEA16C7Da116";

    @Test
    void resolvesFriendlyNamesAndCaip2() {
        assertThat(Networks.resolve("ethereum").id()).isEqualTo("eip155:1");
        assertThat(Networks.resolve("ETH").id()).isEqualTo("eip155:1");
        assertThat(Networks.resolve("sepolia").id()).isEqualTo("eip155:11155111");
        assertThat(Networks.resolve("eip155:11155111").canonical()).isEqualTo("sepolia");
        assertThat(Networks.resolve("bitcoin").id()).startsWith("bip122:");
    }

    @Test
    void passesThroughAnUnlistedButValidCaip2() {
        Networks.Network net = Networks.resolve("eip155:42161");
        assertThat(net.id()).isEqualTo("eip155:42161");
        assertThat(net.defaultAsset()).as("we cannot guess the native asset").isNull();
    }

    @Test
    void rejectsSomethingThatIsNeither() {
        assertThatThrownBy(() -> Networks.resolve("ethreum"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unknown network")
                .hasMessageContaining("ethereum");
    }

    @Test
    void buildsCaip10FromABareAddress() {
        assertThat(Networks.toCaip10(Networks.resolve("sepolia"), ADDR))
                .isEqualTo("eip155:11155111:" + ADDR);
    }

    @Test
    void acceptsAnAddressThatAlreadyNamesTheSameChain() {
        Networks.Network sepolia = Networks.resolve("sepolia");
        assertThat(Networks.toCaip10(sepolia, "eip155:11155111:" + ADDR)).isEqualTo("eip155:11155111:" + ADDR);
        assertThat(Networks.toCaip10(sepolia, "did:pkh:eip155:11155111:" + ADDR)).isEqualTo("eip155:11155111:" + ADDR);
    }

    /** The trap: a bare address must never be silently attributed to another chain. */
    @Test
    void rejectsAnAddressWhoseChainContradictsTheNetwork() {
        assertThatThrownBy(() -> Networks.toCaip10(Networks.resolve("ethereum"), "eip155:11155111:" + ADDR))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("names chain")
                .hasMessageContaining("eip155:11155111");
    }

    @Test
    void sameHexOnTwoChainsIsTwoDifferentRegistrations() {
        assertThat(Networks.toCaip10(Networks.resolve("ethereum"), ADDR))
                .isNotEqualTo(Networks.toCaip10(Networks.resolve("sepolia"), ADDR));
    }
}
