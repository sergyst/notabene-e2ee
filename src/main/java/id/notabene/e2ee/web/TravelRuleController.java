package id.notabene.e2ee.web;

import id.notabene.e2ee.config.NotabeneProperties;
import id.notabene.e2ee.ivms.Channel;
import id.notabene.e2ee.ivms.PiiMode;
import id.notabene.e2ee.ivms.SamplePii;
import id.notabene.e2ee.service.AddressOwnershipService;
import id.notabene.e2ee.service.DemoService;
import id.notabene.e2ee.service.PollingService;
import id.notabene.e2ee.service.TransferService;
import id.notabene.e2ee.service.TravelRuleService;
import id.notabene.e2ee.vasp.VaspKeyStore;
import id.notabene.e2ee.vasp.VaspKeypair;
import id.notabene.e2ee.web.dto.AddOwnershipRequest;
import id.notabene.e2ee.web.dto.AddOwnershipResponse;
import id.notabene.e2ee.web.dto.AddressOwnership;
import id.notabene.e2ee.web.dto.DemoReport;
import id.notabene.e2ee.web.dto.PollRequest;
import id.notabene.e2ee.web.dto.PollStatus;
import id.notabene.e2ee.web.dto.SendRequest;
import id.notabene.e2ee.web.dto.SendResponse;
import id.notabene.e2ee.web.dto.TransferDetail;
import id.notabene.e2ee.web.dto.TransferSummary;
import id.notabene.e2ee.web.dto.VaspInfo;
import jakarta.validation.Valid;
import java.util.ArrayList;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class TravelRuleController {

    private final NotabeneProperties properties;
    private final DemoService demoService;
    private final TravelRuleService travelRuleService;
    private final PollingService pollingService;
    private final TransferService transferService;
    private final VaspKeyStore keyStore;
    private final SamplePii samplePii;
    private final AddressOwnershipService addressOwnershipService;

    public TravelRuleController(NotabeneProperties properties, DemoService demoService,
            TravelRuleService travelRuleService, PollingService pollingService,
            TransferService transferService, VaspKeyStore keyStore, SamplePii samplePii,
            AddressOwnershipService addressOwnershipService) {
        this.properties = properties;
        this.demoService = demoService;
        this.travelRuleService = travelRuleService;
        this.pollingService = pollingService;
        this.transferService = transferService;
        this.keyStore = keyStore;
        this.samplePii = samplePii;
        this.addressOwnershipService = addressOwnershipService;
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

    /** GET /api/samplePii - the editable IVMS101 template the client starts from. */
    @GetMapping("/samplePii")
    public java.util.Map<String, Object> samplePii() {
        return samplePii.get();
    }

    /** POST /api/send - send a Travel Rule message from one VASP to another. */
    @PostMapping("/send")
    public SendResponse send(@Valid @RequestBody SendRequest request) {
        return travelRuleService.send(request);
    }

    /**
     * GET /api/transfers - transfers for one VASP, or for every configured VASP
     * when no vasp parameter is given, newest first.
     *
     * ?vasp=vaspA&vasp=vaspB   omit for all
     * ?channel=notabene|local
     * ?direction=incoming|outgoing  (Notabene channel only)
     */
    @GetMapping("/transfers")
    public List<TransferSummary> transfers(
            @RequestParam(required = false) List<String> vasp,
            @RequestParam(required = false) String channel,
            @RequestParam(required = false) String direction,
            @RequestParam(required = false, defaultValue = "25") int limit) {
        return transferService.list(vasp, Channel.from(channel), direction, limit);
    }

    /**
     * GET /api/transfers/{id}?vasp=vaspB - one transfer, showing the stored
     * ciphertext next to what this VASP can decrypt from it.
     */
    @GetMapping("/transfers/{transferId}")
    public TransferDetail transfer(
            @PathVariable String transferId,
            @RequestParam String vasp,
            @RequestParam(required = false) String channel) {
        return transferService.detail(vasp, transferId, Channel.from(channel));
    }

    /**
     * GET /api/addressOwnership - does this address have a known owner?
     *
     * ?vasp=vaspA&address=0x2222…&asset=eip155:1/slip44:60
     * The address may be bare, CAIP ("eip155:1:0x…") or a did:pkh.
     */
    @GetMapping("/addressOwnership")
    public AddressOwnership addressOwnership(
            @RequestParam String vasp,
            @RequestParam String address,
            @RequestParam(required = false) String asset) {
        return addressOwnershipService.check(vasp, address, asset);
    }

    /**
     * POST /api/addressOwnership - claim an address, so counterparties can
     * discover who owns it. Upserts and confirms, then re-checks.
     */
    @PostMapping("/addressOwnership")
    public AddOwnershipResponse addAddressOwnership(@Valid @RequestBody AddOwnershipRequest request) {
        return addressOwnershipService.claim(request);
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
