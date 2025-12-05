package net.floodlightcontroller.pucp;

import java.util.*;
import java.util.concurrent.*;

import org.restlet.resource.ServerResource;
import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.representation.Representation;
import org.restlet.routing.Router;
import org.restlet.Context;

import net.floodlightcontroller.core.module.*;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.restserver.RestletRoutable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PacketInRestAPI implements IFloodlightModule, RestletRoutable {

    protected static Logger log = LoggerFactory.getLogger(PacketInRestAPI.class);
    protected IRestApiService restApi;

    private ConcurrentHashMap<String, PacketInStats> globalStats;
    private ConcurrentHashMap<String, SwitchStats> switchStats;
    private ConcurrentHashMap<String, AnomalyAlert> anomalyAlerts;
    private long startTime;

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        log.info("[PACKETIN-API] Initializing");

        try {
            restApi = context.getServiceImpl(IRestApiService.class);
        } catch (Exception e) {
            log.error("[PACKETIN-API] Error: {}", e.getMessage());
            throw new FloodlightModuleException(e);
        }

        globalStats = new ConcurrentHashMap<String, PacketInStats>();
        switchStats = new ConcurrentHashMap<String, SwitchStats>();
        anomalyAlerts = new ConcurrentHashMap<String, AnomalyAlert>();
        startTime = System.currentTimeMillis();
    }

    @Override
    public void startUp(FloodlightModuleContext context) {
        log.info("[PACKETIN-API] Starting");
        restApi.addRestletRoutable(this);
        log.info("[PACKETIN-API] Started - REST endpoints active");
    }

    @Override
    public org.restlet.Restlet getRestlet(Context context) {
        Router router = new Router(context);

        router.attach("/stats", PacketInStatsResource.class);
        router.attach("/protocol/{proto}", ProtocolAnalysisResource.class);
        router.attach("/switch/{dpid}", SwitchAnalysisResource.class);
        router.attach("/flows", FlowsResource.class);
        router.attach("/reset", ResetResource.class);
        router.attach("/anomalies", AnomaliesResource.class);
        router.attach("/test", TestPacketInResource.class);

        return router;
    }

    @Override
    public String basePath() {
        return "/wm/packetin";
    }

    private String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }

    // ===== RESOURCE 1: GET /wm/packetin/stats =====
    public class PacketInStatsResource extends ServerResource {
        @Get("json")
        public String retrieve() {
            try {
                long uptime = System.currentTimeMillis() - startTime;
                StringBuilder r = new StringBuilder();
                r.append("{\"status\":\"active\",");
                r.append("\"uptime_seconds\":").append(uptime/1000).append(",");
                r.append("\"timestamp\":").append(System.currentTimeMillis()).append(",");

                // Protocolos
                r.append("\"protocols\":{");
                PacketInStats tcp = globalStats.get("TCP");
                PacketInStats udp = globalStats.get("UDP");
                PacketInStats arp = globalStats.get("ARP");
                r.append("\"TCP\":").append(tcp != null ? tcp.count : 0).append(",");
                r.append("\"UDP\":").append(udp != null ? udp.count : 0).append(",");
                r.append("\"ARP\":").append(arp != null ? arp.count : 0);
                r.append("},");

                // Total paquetes
                long total = 0;
                for (PacketInStats s : globalStats.values()) {
                    total += s.count;
                }
                r.append("\"total_packets\":").append(total).append(",");

                // Switches
                r.append("\"switches\":[");
                int c = 0;
                for (Map.Entry<String, SwitchStats> e : switchStats.entrySet()) {
                    if (c++ > 0) r.append(",");
                    r.append("{");
                    r.append("\"dpid\":\"").append(esc(e.getKey())).append("\",");
                    r.append("\"packets\":").append(e.getValue().packetCount);
                    r.append("}");
                }
                r.append("]");
                r.append("}");

                log.info("[PACKETIN-API] Stats requested");
                return r.toString();
            } catch (Exception e) {
                return "{\"error\":\"" + esc(e.getMessage()) + "\"}";
            }
        }
    }

    // ===== RESOURCE 2: GET /wm/packetin/protocol/{proto} =====
    public class ProtocolAnalysisResource extends ServerResource {
        @Get("json")
        public String retrieve() {
            try {
                String proto = (String) getRequestAttributes().get("proto");
                PacketInStats stats = globalStats.get(proto);
                if (stats == null) stats = new PacketInStats();

                StringBuilder r = new StringBuilder();
                r.append("{");
                r.append("\"protocol\":\"").append(esc(proto)).append("\",");
                r.append("\"packet_count\":").append(stats.count).append(",");
                r.append("\"byte_count\":").append(stats.bytes).append(",");
                r.append("\"average_size\":").append(stats.count > 0 ? stats.bytes / stats.count : 0);
                r.append("}");

                log.info("[PACKETIN-API] Protocol analysis: {}", proto);
                return r.toString();
            } catch (Exception e) {
                return "{\"error\":\"" + esc(e.getMessage()) + "\"}";
            }
        }
    }

    // ===== RESOURCE 3: GET /wm/packetin/switch/{dpid} =====
    public class SwitchAnalysisResource extends ServerResource {
        @Get("json")
        public String retrieve() {
            try {
                String dpid = (String) getRequestAttributes().get("dpid");
                SwitchStats stats = switchStats.get(dpid);
                if (stats == null) stats = new SwitchStats();

                StringBuilder r = new StringBuilder();
                r.append("{");
                r.append("\"dpid\":\"").append(esc(dpid)).append("\",");
                r.append("\"packet_count\":").append(stats.packetCount).append(",");
                r.append("\"port_count\":").append(stats.ports.size()).append(",");
                r.append("\"uptime\":").append(System.currentTimeMillis() - stats.startTime);
                r.append("}");

                log.info("[PACKETIN-API] Switch analysis: {}", dpid);
                return r.toString();
            } catch (Exception e) {
                return "{\"error\":\"" + esc(e.getMessage()) + "\"}";
            }
        }
    }

    // ===== RESOURCE 4: GET /wm/packetin/flows =====
    public class FlowsResource extends ServerResource {
        @Get("json")
        public String retrieve() {
            try {
                Map<String, FlowRecord> flows = getActiveFlows();
                StringBuilder r = new StringBuilder();
                r.append("{");
                r.append("\"total_flows\":").append(flows.size()).append(",");
                r.append("\"flows\":[]");
                r.append("}");

                log.info("[PACKETIN-API] Flows requested");
                return r.toString();
            } catch (Exception e) {
                return "{\"error\":\"" + esc(e.getMessage()) + "\"}";
            }
        }
    }

    // ===== RESOURCE 5: GET /wm/packetin/anomalies =====
    public class AnomaliesResource extends ServerResource {
        @Get("json")
        public String retrieve() {
            try {
                int critical = 0, warning = 0;
                for (AnomalyAlert a : anomalyAlerts.values()) {
                    if (a.severity > 80) critical++;
                    else if (a.severity > 40) warning++;
                }

                StringBuilder r = new StringBuilder();
                r.append("{");
                r.append("\"total_anomalies\":").append(anomalyAlerts.size()).append(",");
                r.append("\"critical_count\":").append(critical).append(",");
                r.append("\"warning_count\":").append(warning).append(",");
                r.append("\"anomalies\":[]");
                r.append("}");

                log.info("[PACKETIN-API] Anomalies requested");
                return r.toString();
            } catch (Exception e) {
                return "{\"error\":\"" + esc(e.getMessage()) + "\"}";
            }
        }
    }

    // ===== RESOURCE 6: POST /wm/packetin/reset =====
    public class ResetResource extends ServerResource {
        @Post("json")
        public String reset(Representation entity) {
            try {
                globalStats.clear();
                switchStats.clear();
                anomalyAlerts.clear();
                startTime = System.currentTimeMillis();

                log.info("[PACKETIN-API] Stats reset");
                return "{\"status\":\"reset_successful\",\"timestamp\":" + System.currentTimeMillis() + "}";
            } catch (Exception e) {
                return "{\"error\":\"" + esc(e.getMessage()) + "\"}";
            }
        }
    }

    // ===== RESOURCE 7: GET /wm/packetin/test =====
    public class TestPacketInResource extends ServerResource {
        @Get("json")
        public String test() {
            try {
                long total = 0;
                for (PacketInStats s : globalStats.values()) {
                    total += s.count;
                }

                StringBuilder r = new StringBuilder();
                r.append("{");
                r.append("\"status\":\"online\",");
                r.append("\"module\":\"PacketInRestAPI\",");
                r.append("\"version\":\"1.0\",");
                r.append("\"total_packets\":").append(total).append(",");
                r.append("\"switches\":").append(switchStats.size()).append(",");
                r.append("\"anomalies\":").append(anomalyAlerts.size());
                r.append("}");

                log.info("[PACKETIN-API] Test successful");
                return r.toString();
            } catch (Exception e) {
                return "{\"error\":\"" + esc(e.getMessage()) + "\"}";
            }
        }
    }

    // ===== INNER CLASSES =====
    public class PacketInStats {
        public long count = 0;
        public long bytes = 0;
        public ConcurrentHashMap<String, Long> sourceFrequency = new ConcurrentHashMap<String, Long>();
        public ConcurrentHashMap<String, Long> destFrequency = new ConcurrentHashMap<String, Long>();
    }

    public class SwitchStats {
        public long packetCount = 0;
        public long lastPacketTime = System.currentTimeMillis();
        public long startTime = System.currentTimeMillis();
        public ConcurrentHashMap<Integer, Long> ports = new ConcurrentHashMap<Integer, Long>();
        public ConcurrentHashMap<String, Long> protocolCount = new ConcurrentHashMap<String, Long>();
    }

    public class AnomalyAlert {
        public String id;
        public String type;
        public int severity;
        public String source;
        public String destination;
        public String description;
        public long timestamp;
        public String status;

        public AnomalyAlert(String type, String src, String dst, int sev, String desc) {
            this.id = UUID.randomUUID().toString();
            this.type = type;
            this.source = src;
            this.destination = dst;
            this.severity = sev;
            this.description = desc;
            this.timestamp = System.currentTimeMillis();
            this.status = "active";
        }
    }

    public class FlowRecord {
        public String srcIP;
        public String dstIP;
        public int srcPort;
        public int dstPort;
        public String protocol;
        public long packetCount;
        public long byteCount;
        public long createdTime;
        public long lastSeen;

        public FlowRecord(String src, String dst, int sp, int dp, String proto) {
            this.srcIP = src;
            this.dstIP = dst;
            this.srcPort = sp;
            this.dstPort = dp;
            this.protocol = proto;
            this.createdTime = System.currentTimeMillis();
            this.lastSeen = createdTime;
        }
    }

    private Map<String, FlowRecord> getActiveFlows() {
        return new ConcurrentHashMap<String, FlowRecord>();
    }

    // ===== IFloodlightModule =====
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return Collections.emptyList();
    }

    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return Collections.emptyMap();
    }

    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IRestApiService.class);
        return l;
    }

    public String getName() {
        return "PacketInRestAPI";
    }

    public boolean isCallbackOrderingPrereq(String type, String name) {
        return false;
    }

    public boolean isCallbackOrderingPostreq(String type, String name) {
        return false;
    }
}
