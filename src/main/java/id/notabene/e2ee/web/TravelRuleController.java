package id.notabene.e2ee.web;

import id.notabene.e2ee.config.NotabeneProperties;
import id.notabene.e2ee.ivms.PiiMode;
import id.notabene.e2ee.service.DemoService;
import id.notabene.e2ee.service.PollingService;
import id.notabene.e2ee.service.TravelRuleService;
import id.notabene.e2ee.vasp.VaspKeyStore;
import id.notabene.e2ee.vasp.VaspKeypair;
import id.notabene.e2ee.web.dto.DemoReport;
import id.notabene.e2ee.web.dto.PollRequest;
import id.notabene.e2ee.web.dto.PollStatus;
import id.notabene.e2ee.web.dto.SendRequest;
import id.notabene.e2ee.web.dto.SendResponse;
import id.notabene.e2ee.web.dto.VaspInfo;
import jakarta.validation.Valid;
import java.util.ArrayList;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class TravelRuleController {

    private final NotabeneProperties properties;
    private final DemoService demoService;
    private final TravelRuleService travelRuleService;
    private final PollingService pollingService;
    private final VaspKeyStore keyStore;

    public TravelRuleController(NotabeneProperties properties, DemoService demoService,
            TravelRuleService travelRuleService, PollingService pollingService, VaspKeyStore keyStore) {
        this.properties = properties;
        this.demoService = demoService;
        this.travelRuleService = travelRuleService;
        this.pollingService = pollingService;
        this.keyStore = keyStore;
    }

    /**
     * The offline round trip: vaspA encrypts, vaspB decrypts, and the response
     * shows the PII matching field by field. Needs no credentials.
     * <p>
     * GET /api/demo?mode=branch|field
     */
    @GetMapping("/demo")
    public DemoReport demo(@RequestParam(required = false) String mode) {
        return demoService.run(mode == null ? PiiMode.from(properties.getPiiMode()) : PiiMode.from(mode));
    }

    /** POST /api/send - send a Travel Rule message from one VASP to another. */
    @PostMapping("/send")
    public SendResponse send(@Valid @RequestBody SendRequest request) {
        return travelRuleService.send(request);
    }

    /** POST /api/startPool - start polling Notabene for messages to this VASP. */
    @PostMapping("/startPool")
    public PollStatus startPool(@Valid @RequestBody PollRequest request) {
        return pollingService.start(request.vasp(), request.intervalSeconds());
    }

    /** POST /api/stopPool - stop that poller. */
    @PostMapping("/stopPool")
    public PollStatus stopPool(@Valid @RequestBody PollRequest request) {
        return pollingService.stop(request.vasp());
    }

    /** GET /api/pollStatus - which pollers are running, and what they have decrypted. */
    @GetMapping("/pollStatus")
    public List<PollStatus> pollStatus() {
        return pollingService.statuses();
    }

    /**
     * GET /api/vasps - the configured VASPs with the public half of their PII
     * keys and a ready-to-paste DIDDoc entry. Start here when registering test
     * VASPs with Notabene.
     */
    @GetMapping("/vasps")
    public List<VaspInfo> vasps() {
        List<VaspInfo> out = new ArrayList<>();
        properties.getVasps().forEach((name, vasp) -> {
            VaspKeypair keypair = keyStore.keypairFor(name);
            out.add(new VaspInfo(
                    name,
                    vasp.getDid(),
                    keypair.kid(),
                    keypair.publicKeyHex(),
                    vasp.hasCredentials(),
                    keyStore.keyFile(name).toString(),
                    keypair.didDocEntry(),
                    keypair.didDocEntryHexVariant(),
                    "Replace the #notabene-pii entry in this entity's DIDDoc with didDocEntry (or add it "
                            + "as \"" + keypair.kid() + "\"), add that id to keyAgreement, and turn OFF "
                            + "Notabene-managed encryption in the Dashboard. Sandbox DIDDocs are hosted by "
                            + "Notabene - ask their support to publish the updated document."));
        });
        return out;
    }
}
