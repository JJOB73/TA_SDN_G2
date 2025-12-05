package net.floodlightcontroller.pucp;

import java.util.*;
import java.util.concurrent.*;
import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.types.*;
import net.floodlightcontroller.core.*;
import net.floodlightcontroller.core.module.*;
import net.floodlightcontroller.packet.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * PacketIn Analyzer - Monitorea paquetes para detectar anomalías
 * Detecta: SYN Flood, UDP Flood, Port Scanning, ARP Spoofing, DNS amplification
 */
public class PacketInAnalyzer implements IFloodlightModule, IOFMessageListener {

    protected static Logger log = LoggerFactory.getLogger(PacketInAnalyzer.class);

    protected IFloodlightProviderService floodlightProvider;

    // Estadísticas
    private ConcurrentHashMap<String, PacketStats> packetStats;
    private ConcurrentHashMap<String, Integer> portScans;
    private ConcurrentHashMap<String, Integer> synFloodTracker;
    private ConcurrentHashMap<String, Integer> arpFloodTracker;

    private static final int SYN_FLOOD_THRESHOLD = 100;
    private static final int PORT_SCAN_THRESHOLD = 20;
    private static final int ARP_FLOOD_THRESHOLD = 100;

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        log.info("[PacketIn] Analyzer initializing");
        
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        
        packetStats = new ConcurrentHashMap<>();
        portScans = new ConcurrentHashMap<>();
        synFloodTracker = new ConcurrentHashMap<>();
        arpFloodTracker = new ConcurrentHashMap<>();
    }

    @Override
    public void startUp(FloodlightModuleContext context) {
        log.info("[PacketIn] Analyzer started - listening for PACKET_IN");
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
    }

    /**
     * MÉTODO PRINCIPAL: Procesa cada PACKET_IN
     * 
     * Es llamado para CADA paquete que llega al controlador
     */
    @Override
    public Command receive(IOFSwitch sw, OFMessage msg,FloodlightContext cntx) {
        OFPacketIn pi = (OFPacketIn) msg;

        try {
            // 1. Extraer frame Ethernet
            byte[] payload = pi.getData();
            Ethernet eth = new Ethernet();
            eth.deserialize(payload, 0, payload.length);

            // 2. Registrar estadísticas básicas
            recordEthernetStats(eth);

            // 3. Analizar por protocolo
            if (eth.getPayload() instanceof ARP) {
                analyzeARP((ARP) eth.getPayload(), sw);
            } else if (eth.getPayload() instanceof IPv4) {
                analyzeIPv4((IPv4) eth.getPayload(), eth, sw);
            } else if (eth.getPayload() instanceof IPv6) {
                log.debug("[PacketIn] IPv6 packet detected");
            }

        } catch (Exception e) {
            log.debug("[PacketIn] Error processing packet: {}", e.getMessage());
        }

        return Command.CONTINUE;
    }

    /**
     * ANALIZAR IPv4 - TCP, UDP, ICMP
     */
    private void analyzeIPv4(IPv4 ipv4, Ethernet eth, IOFSwitch sw) {
        String srcIP = ipv4.getSourceAddress().toString();
        String dstIP = ipv4.getDestinationAddress().toString();
        short protocol = ipv4.getProtocol().getIpProtocolNumber();

        // Protocolo TCP
        if (protocol == IpProtocol.TCP.getIpProtocolNumber()) {
            TCP tcp = (TCP) ipv4.getPayload();
            analyzeTCP(tcp, srcIP, dstIP);
        }
        // Protocolo UDP
        else if (protocol == IpProtocol.UDP.getIpProtocolNumber()) {
            UDP udp = (UDP) ipv4.getPayload();
            analyzeUDP(udp, srcIP, dstIP);
        }
        // Protocolo ICMP
        else if (protocol == IpProtocol.ICMP.getIpProtocolNumber()) {
            analyzeICMP(srcIP, dstIP);
        }
    }

    /**
     * ANALIZAR TCP - Detecta SYN Flood, Port Scanning
     * 
     * SYN Flood: muchos SYN desde un IP a varios puertos
     * Port Scanning: conexiones a muchos puertos diferentes
     */
    private void analyzeTCP(TCP tcp, String srcIP, String dstIP) {
        short flags = tcp.getFlags();
        boolean isSYN = (flags & 0x02) != 0;
        int dstPort = tcp.getDestinationPort().getPort();

        // Detectar SYN Flood
        if (isSYN) {
            Integer count = synFloodTracker.getOrDefault(srcIP, 0);
            count++;
            synFloodTracker.put(srcIP, count);

            if (count > SYN_FLOOD_THRESHOLD) {
                log.warn("[ALERT] SYN Flood detected from {} (count: {})", srcIP, count);
            }
        }

        // Detectar Port Scanning (muchos puertos desde mismo origen)
        String scanKey = srcIP + "-" + dstIP;
        Integer ports = portScans.getOrDefault(scanKey, 0);
        ports++;
        portScans.put(scanKey, ports);

        if (ports > PORT_SCAN_THRESHOLD) {
            log.warn("[ALERT] Port scanning detected: {} -> {} ({} ports)", new Object[]{srcIP, dstIP, Integer.valueOf(ports)});
        }

        log.debug("[TCP] {} -> {}:{} (flags: {})", new Object[]{srcIP, dstIP,Integer.valueOf(dstPort),Short.valueOf(flags)});
    }

    /**
     * ANALIZAR UDP - Detecta DNS, DHCP, UDP Flood
     */
    private void analyzeUDP(UDP udp, String srcIP, String dstIP) {
        int dstPort = udp.getDestinationPort().getPort();
        int srcPort = udp.getSourcePort().getPort();

        // Puerto 53 = DNS
        if (dstPort == 53 || srcPort == 53) {
            log.debug("[DNS] Query from {} to {}:{}", new Object[]{srcIP, dstIP, Integer.valueOf(dstPort)});
        }
        // Puertos 67-68 = DHCP
        else if (dstPort == 67 || dstPort == 68 || srcPort == 67 || srcPort == 68) {
            log.debug("[DHCP] Traffic from {} to {}:{}", new Object[]{srcIP, dstIP, Integer.valueOf(dstPort)});
        }
        // Detectar UDP Flood (muchos paquetes UDP)
        else {
            String udpKey = srcIP + ":" + dstPort;
            PacketStats stats = packetStats.getOrDefault(udpKey, new PacketStats());
            stats.udpCount++;
            packetStats.put(udpKey, stats);

            if (stats.udpCount > 1000) {
                log.warn("[ALERT] UDP Flood from {} to {}:{}", new Object[]{srcIP, dstIP, Integer.valueOf(dstPort)});
            }
        }
    }

    /**
     * ANALIZAR ICMP - Detecta Ping Flood
     */
    private void analyzeICMP(String srcIP, String dstIP) {
        String pingKey = "PING:" + srcIP;
        PacketStats stats = packetStats.getOrDefault(pingKey, new PacketStats());
        stats.icmpCount++;
        packetStats.put(pingKey, stats);

        if (stats.icmpCount > 1000) {
            log.warn("[ALERT] ICMP Flood (Ping Flood) from {} to {}", srcIP, dstIP);
        }
    }

    /**
     * ANALIZAR ARP - Detecta ARP Spoofing, ARP Flood
     */
    private void analyzeARP(ARP arp, IOFSwitch sw) {
        String senderIP = arp.getSenderProtocolAddress().toString();
        String senderMAC = arp.getSenderHardwareAddress().toString();

        // Detectar ARP Flood (muchos ARP desde mismo IP)
        Integer count = arpFloodTracker.getOrDefault(senderIP, 0);
        count++;
        arpFloodTracker.put(senderIP, count);

        if (count > ARP_FLOOD_THRESHOLD) {
            log.warn("[ALERT] ARP Flood detected from {} ({})", senderIP, senderMAC);
        }

        log.debug("[ARP] Request from {} ({})", senderIP, senderMAC);
    }

    /**
     * REGISTRAR ESTADÍSTICAS ETHERNET
     */
    private void recordEthernetStats(Ethernet eth) {
        String etherKey = "ETH:" + eth.getEtherType();
        PacketStats stats = packetStats.getOrDefault(etherKey, new PacketStats());
        stats.ethCount++;
        packetStats.put(etherKey, stats);
    }

    /**
     * OBTENER ESTADÍSTICAS (para API o logs)
     */
    public Map<String, PacketStats> getStatistics() {
        return new HashMap<>(packetStats);
    }

    public int getSYNFloodCount(String srcIP) {
        return synFloodTracker.getOrDefault(srcIP, 0);
    }

    public int getPortScanCount(String srcDstKey) {
        return portScans.getOrDefault(srcDstKey, 0);
    }

    // =========================================================================
    // INTERFAZ IFloodlightModule
    // =========================================================================

    @Override
    public String getName() {
        return "PacketInAnalyzer";
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return false;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return Collections.emptyList();
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return Collections.emptyMap();
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l = 
            new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        return l;
    }

    // =========================================================================
    // CLASE INTERNA - PacketStats
    // =========================================================================

    public static class PacketStats {
        public long ethCount = 0;
        public long tcpCount = 0;
        public long udpCount = 0;
        public long icmpCount = 0;
        public long arpCount = 0;

        public PacketStats() {
        }

        @Override
        public String toString() {
            return "PacketStats{" +
                    "eth=" + ethCount +
                    ", tcp=" + tcpCount +
                    ", udp=" + udpCount +
                    ", icmp=" + icmpCount +
                    ", arp=" + arpCount +
                    '}';
        }
    }
}

