package id.notabene.e2ee.service;

import id.notabene.e2ee.config.NotabeneProperties;
import id.notabene.e2ee.ivms.IvmsCrypto;
import id.notabene.e2ee.vasp.VaspKeyStore;
import id.notabene.e2ee.vasp.VaspKeypair;
import id.notabene.e2ee.web.dto.PollStatus;
import id.notabene.e2ee.web.dto.ReceivedMessage;
import jakarta.annotation.PreDestroy;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.stereotype.Service;

/**
 * Polls Notabene for incoming Travel Rule messages on behalf of a VASP and
 * decrypts them locally.
 *
 * A webhook subscription to tap.requirePresentationSatisfied is the push
 * alternative, but polling needs no public URL, which makes it far easier to
 * try from a laptop.
 */
@Service
public class PollingService {

    private static final Logger log = LoggerFactory.getLogger(PollingService.class);

    private final NotabeneProperties properties;
    private final id.notabene.e2ee.notabene.NotabeneClient client;
    private final IvmsCrypto ivmsCrypto;
    private final VaspKeyStore keyStore;
    private final ThreadPoolTaskScheduler scheduler;

    private final Map<String, Poller> pollers = new ConcurrentHashMap<>();

    private static final class Poller {
        final String vaspName;
        final int intervalSeconds;
        final Instant startedAt = Instant.now();
        final Set<String> seenTransferIds = Collections.synchronizedSet(new LinkedHashSet<>());
        final Deque<ReceivedMessage> history = new ArrayDeque<>();
        final AtomicInteger polls = new AtomicInteger();
        final AtomicInteger decrypted = new AtomicInteger();
        final AtomicReference<String> lastError = new AtomicReference<>();
        volatile ScheduledFuture<?> future;

        Poller(String vaspName, int intervalSeconds) {
            this.vaspName = vaspName;
            this.intervalSeconds = intervalSeconds;
        }
    }

    public PollingService(NotabeneProperties properties, id.notabene.e2ee.notabene.NotabeneClient client,
            IvmsCrypto ivmsCrypto, VaspKeyStore keyStore) {
        this.properties = properties;
        this.client = client;
        this.ivmsCrypto = ivmsCrypto;
        this.keyStore = keyStore;

        this.scheduler = new ThreadPoolTaskScheduler();
        this.scheduler.setPoolSize(4);
        this.scheduler.setThreadNamePrefix("tr-poll-");
        this.scheduler.setWaitForTasksToCompleteOnShutdown(false);
        this.scheduler.initialize();
    }

    public PollStatus start(String vaspName, Integer intervalSeconds) {
        properties.requireVasp(vaspName); // fail fast on an unknown name
        int interval = (intervalSeconds == null || intervalSeconds <= 0)
                ? properties.getPolling().getDefaultIntervalSeconds()
                : intervalSeconds;

        Poller existing = pollers.get(vaspName);
        if (existing != null) {
            log.info("poller for {} is already running every {}s", vaspName, existing.intervalSeconds);
            return status(existing, true, "already running");
        }

        Poller poller = new Poller(vaspName, interval);
        // Touch the keypair now so a missing key fails here, not on a background thread.
        VaspKeypair keypair = keyStore.keypairFor(vaspName);
        poller.future = scheduler.scheduleWithFixedDelay(
                () -> pollOnce(poller), java.time.Duration.ofSeconds(interval));
        pollers.put(vaspName, poller);

        log.info("started polling for {} every {}s, decrypting with {}", vaspName, interval, keypair.kid());
        return status(poller, true, "started");
    }

    public PollStatus stop(String vaspName) {
        Poller poller = pollers.remove(vaspName);
        if (poller == null) {
            log.info("no poller running for {}", vaspName);
            return new PollStatus(vaspName, false, 0, null, 0, 0, null, List.of(), "not running");
        }
        if (poller.future != null) {
            poller.future.cancel(false);
        }
        log.info("stopped polling for {} after {} poll(s), {} decrypted message(s)",
                vaspName, poller.polls.get(), poller.decrypted.get());
        return status(poller, false, "stopped");
    }

    public List<PollStatus> statuses() {
        List<PollStatus> out = new ArrayList<>();
        pollers.values().forEach(poller -> out.add(status(poller, true, "running")));
        return out;
    }

    private void pollOnce(Poller poller) {
        poller.polls.incrementAndGet();
        try {
            NotabeneProperties.Vasp vasp = properties.requireVasp(poller.vaspName);
            VaspKeypair keypair = keyStore.keypairFor(poller.vaspName);

            List<Map<String, Object>> transfers = client.listTransfers(
                    vasp, properties.getPolling().getDirection(), properties.getPolling().getLimit());

            for (Map<String, Object> summary : transfers) {
                Object idValue = summary.get("id");
                if (idValue == null) {
                    continue;
                }
                String transferId = idValue.toString();
                if (!poller.seenTransferIds.add(transferId)) {
                    continue; // already handled
                }

                // decrypt=false: we want the ciphertext, not Notabene's copy.
                Map<String, Object> full = client.getTransfer(vasp, transferId, false);
                Map<String, Object> encryptedIvms = ivmsCrypto.findIvms(full);
                if (encryptedIvms == null) {
                    log.debug("{}: transfer {} has no ivms101 yet", poller.vaspName, transferId);
                    poller.seenTransferIds.remove(transferId); // look again next tick
                    continue;
                }

                try {
                    IvmsCrypto.DecryptResult result = ivmsCrypto.decrypt(
                            encryptedIvms, keypair.privateJwk(), null, keypair.kid());
                    poller.decrypted.incrementAndGet();

                    log.info("{}: decrypted {} JWE(s) from transfer {}",
                            poller.vaspName, result.parts().size(), transferId);
                    ivmsCrypto.flattenLeaves(result.payload()).forEach(leaf ->
                            log.info("    {} = {}", leaf.path().replaceFirst("^\\$\\.?", ""), leaf.value()));

                    ReceivedMessage message = new ReceivedMessage(
                            transferId,
                            Instant.now(),
                            String.valueOf(full.getOrDefault("status",
                                    asMap(full.get("transfer")).getOrDefault("status", "unknown"))),
                            result.parts().size(),
                            result.payload());
                    synchronized (poller.history) {
                        poller.history.addFirst(message);
                        while (poller.history.size() > properties.getPolling().getHistorySize()) {
                            poller.history.removeLast();
                        }
                    }
                } catch (RuntimeException e) {
                    log.warn("{}: could not decrypt transfer {}: {}", poller.vaspName, transferId, e.getMessage());
                }
            }
            poller.lastError.set(null);
        } catch (RuntimeException e) {
            poller.lastError.set(e.getMessage());
            log.warn("{}: poll failed: {}", poller.vaspName, e.getMessage());
        }
    }

    private PollStatus status(Poller poller, boolean running, String message) {
        List<ReceivedMessage> history;
        synchronized (poller.history) {
            history = List.copyOf(poller.history);
        }
        return new PollStatus(
                poller.vaspName,
                running,
                poller.intervalSeconds,
                poller.startedAt,
                poller.polls.get(),
                poller.decrypted.get(),
                poller.lastError.get(),
                history,
                message);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        return value instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
    }

    @PreDestroy
    void shutdown() {
        pollers.keySet().forEach(this::stop);
        scheduler.shutdown();
    }
}
