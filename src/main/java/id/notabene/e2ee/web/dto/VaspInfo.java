package id.notabene.e2ee.web.dto;

import java.util.Map;

/** What you need to register a VASP with Notabene, minus the private key. */
public record VaspInfo(
        String name,
        String did,
        String kid,
        String publicKeyHex,
        boolean credentialsConfigured,
        String keyFile,
        Map<String, Object> didDocEntry,
        Map<String, Object> didDocEntryHexVariant,
        String publishHint) {
}
