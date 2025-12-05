package net.floodlightcontroller.pucp;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;

/**
 * Simple DHCP Manager module for Floodlight.
 * Does NOT send Ethernet packets. It only manages internal DHCP state.
 * Useful for labs or for integrating with other modules.
 */
public class DHCPManager implements IFloodlightModule {

    protected static Logger log = LoggerFactory.getLogger(DHCPManager.class);

    /** Stores active IP leases: MAC -> Lease */
    private Map<String, DHCPLease> activeLeases;

    /** Pool of available IP addresses */
    private List<String> availableIPs;

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        log.info("[DHCP] Module initializing");
        activeLeases = new HashMap<String, DHCPLease>();
        availableIPs = new ArrayList<String>();

        initializePool("192.168.250.50", "192.168.250.80");
    }

    @Override
    public void startUp(FloodlightModuleContext context) {
        log.info("[DHCP] Module started");
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        return Collections.emptyList();
    }

    // -------------------------------------------------------------------------
    // DHCP LOGIC
    // -------------------------------------------------------------------------

    /** Creates a list of IPs between start and end (inclusive). */
    private void initializePool(String startIP, String endIP) {
        List<String> list = generateRange(startIP, endIP);
        availableIPs.addAll(list);
        log.info("[DHCP] Loaded {} IPs into pool", Integer.valueOf(list.size()));
    }

    /** Simplified DHCP DISCOVER: returns an available IP or null. */
    public String processDiscover(String mac) {
        log.info("[DHCP] DISCOVER from {}", mac);

        if (activeLeases.containsKey(mac)) {
            DHCPLease lease = activeLeases.get(mac);
            log.info("[DHCP] DISCOVER: MAC {} already has {}", mac, lease.getIp());
            return lease.getIp();
        }

        if (availableIPs.isEmpty()) {
            log.warn("[DHCP] No more IPs available for {}", mac);
            return null;
        }

        String ip = availableIPs.remove(0);
        activeLeases.put(mac, new DHCPLease(mac, ip, System.currentTimeMillis()));

        log.info("[DHCP] OFFER: {} assigned to {}", ip, mac);
        return ip;
    }

    /** DHCP REQUEST: confirms lease or rejects it. */
    public boolean processRequest(String mac, String requestedIP) {
        DHCPLease lease = activeLeases.get(mac);

        if (lease == null) {
            log.warn("[DHCP] REQUEST rejected: {} has no lease", mac);
            return false;
        }

        if (!lease.getIp().equals(requestedIP)) {
            log.warn("[DHCP] REQUEST mismatch: {} requested {}, expected {}",
                new Object[]{mac, requestedIP, lease.getIp()});
            return false;
        }

        log.info("[DHCP] REQUEST confirmed: {} keeps {}", mac, requestedIP);
        return true;
    }

    /** DHCP RELEASE: returns IP to the pool. */
    public void processRelease(String mac) {
        DHCPLease lease = activeLeases.remove(mac);

        if (lease == null) {
            log.info("[DHCP] RELEASE: {} had no lease", mac);
            return;
        }

        availableIPs.add(lease.getIp());
        log.info("[DHCP] RELEASE: {} returned IP {}", mac, lease.getIp());
    }

    /** Removes expired leases (if timeout policy needed later). */
    public void cleanup() {
        Iterator<Map.Entry<String, DHCPLease>> it = activeLeases.entrySet().iterator();

        while (it.hasNext()) {
            Map.Entry<String, DHCPLease> entry = it.next();
            DHCPLease lease = entry.getValue();

            // Example expiration: 1 hour = 3600000 ms
            long now = System.currentTimeMillis();
            if (now - lease.getTimestamp() > 3600000) {
                log.info("[DHCP] Lease expired for {} ({})",
                        entry.getKey(), lease.getIp());

                availableIPs.add(lease.getIp());
                it.remove();
            }
        }
    }

    // -------------------------------------------------------------------------
    // HELPER METHODS
    // -------------------------------------------------------------------------

    /** Generates a range of IPs inclusive. */
    private List<String> generateRange(String start, String end) {
        List<String> list = new ArrayList<String>();

        long s = ipToLong(start);
        long e = ipToLong(end);

        for (long i = s; i <= e; i++) {
            list.add(longToIp(i));
        }

        return list;
    }

    private long ipToLong(String ip) {
        String[] parts = ip.split("\\.");
        long res = 0;

        for (int i = 0; i < 4; i++) {
            res = res * 256 + Integer.parseInt(parts[i]);
        }
        return res;
    }

    private String longToIp(long val) {
        return String.format("%d.%d.%d.%d",
                new Object[]{
                    Long.valueOf((val >> 24) & 0xFF),
                    Long.valueOf((val >> 16) & 0xFF),
                    Long.valueOf((val >> 8) & 0xFF),
                    Long.valueOf(val & 0xFF)
                });
    }

    // -------------------------------------------------------------------------
    // INNER CLASS
    // -------------------------------------------------------------------------

    /** Basic DHCP lease structure */
    private static class DHCPLease {
        private String mac;
        private String ip;
        private long timestamp;

        public DHCPLease(String mac, String ip, long timestamp) {
            this.mac = mac;
            this.ip = ip;
            this.timestamp = timestamp;
        }

        public String getMac() {
            return mac;
        }

        public String getIp() {
            return ip;
        }

        public long getTimestamp() {
            return timestamp;
        }
    }
}
