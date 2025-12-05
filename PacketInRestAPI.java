package net.floodlightcontroller.pucp;

import java.util.*;
import java.util.concurrent.*;

import org.restlet.resource.ServerResource;
import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.representation.Representation;
import org.restlet.routing.Router;
import org.restlet.Context;
import org.restlet.Restlet;

import net.floodlightcontroller.core.module.*;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.restserver.RestletRoutable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PacketInRestAPI implements IFloodlightModule, RestletRoutable {

    protected static Logger log = LoggerFactory.getLogger(PacketInRestAPI.class);
    protected IRestApiService restApi;

    // Variable estática para acceso desde recursos estáticos
    protected static PacketInRestAPI instance;

    protected ConcurrentHashMap<String, PacketInStats> globalStats;
    protected ConcurrentHashMap<String, SwitchStats> switchStats;
    protected ConcurrentHashMap<String, AnomalyAlert> anomalyAlerts;
    protected long startTime;

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        log.info("[PACKETIN-API] Initializing");

        restApi = context.getServiceImpl(IRestApiService.class);

        globalStats = new ConcurrentHashMap<String, PacketInStats>();
        switchStats = new ConcurrentHashMap<String, SwitchStats>();
        anomalyAlerts = new ConcurrentHashMap<String, AnomalyAlert>();
        startTime = System.currentTimeMillis();
        
        // Guardar instancia para acceso estático
        instance = this;
    }

    @Override
    public void startUp(FloodlightModuleContext context) {
        log.info("[PACKETIN-API] Starting");

        restApi.addRestletRoutable(this);

        log.info("[PACKETIN-API] Started - REST endpoints active");
    }

    @Override
    public Restlet getRestlet(Context context) {
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

    protected String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }


    /* ============================================================
     *   REST RESOURCES (all must be static)
     * ============================================================ */

    // ===== RESOURCE 1: GET /wm/packetin/stats =====
    public static class PacketInStatsResource extends ServerResource {
        @Get("json")
        public String retrieve() {
            try {
                PacketInRestAPI module = instance;

                long uptime = System.currentTimeMillis() - module.startTime;

                StringBuilder r = new StringBuilder();
                r.append("{\"status\":\"active\",");
                r.append("\"uptime_seconds\":").append(uptime / 1000).append(",");
                r.append("\"timestamp\":").append(System.currentTimeMillis()).append(",");

                // Protocols
                r.append("\"protocols\":{");
                PacketInStats tcp = module.globalStats.get("TCP");
                PacketInStats udp = module.globalStats.get("UDP");
                PacketInStats arp = module.globalStats.get("ARP");
                r.append("\"TCP\":").append(tcp != null ? tcp.count : 0).append(",");
                r.append("\"UDP\":").append(udp != null ? udp.count : 0).append(",");
                r.append("\"ARP\":").append(arp != null ? arp.count : 0);
                r.append("},");

                long total = 0;
                for (PacketInStats s : module.globalStats.values()) {
                    total += s.count;
                }

                // Switch stats
                r.append("\"switches\":[");
                int idx = 0;
                for (Map.Entry<String, SwitchStats> e : module.switchStats.entrySet()) {
                    if (idx++ > 0) r.append(",");
                    r.append("{\"dpid\":\"").append(module.esc(e.getKey())).append("\",");
                    r.append("\"packets\":").append(e.getValue().packetCount).append("}");
                }
                r.append("]}");

                return r.toString();

            } catch (Exception e) {
                return "{\"error\":\"" + e.getMessage() + "\"}";
            }
        }
    }


    // ===== RESOURCE 2: GET /wm/packetin/protocol/{proto} =====
    public static class ProtocolAnalysisResource extends ServerResource {
        @Get("json")
        public String retrieve() {
            try {
                PacketInRestAPI module = instance;

                String proto = (String) getRequestAttributes().get("proto");
                PacketInStats stats = module.globalStats.get(proto);

                if (stats == null) {
                    stats = module.new PacketInStats();
                }

                StringBuilder r = new StringBuilder();
                r.append("{\"protocol\":\"").append(module.esc(proto)).append("\",");
                r.append("\"packet_count\":").append(stats.count).append(",");
                r.append("\"byte_count\":").append(stats.bytes).append(",");
                r.append("\"average_size\":").append(stats.count > 0 ? stats.bytes / stats.count : 0).append("}");

                return r.toString();

            } catch (Exception e) {
                return "{\"error\":\"" + e.getMessage() + "\"}";
            }
        }
    }


    // ===== RESOURCE 3: GET /wm/packetin/switch/{dpid} =====
    public static class SwitchAnalysisResource extends ServerResource {
        @Get("json")
        public String retrieve() {
            try {
                PacketInRestAPI module = instance;

                String dpid = (String) getRequestAttributes().get("dpid");
                SwitchStats stats = module.switchStats.get(dpid);
                if (stats == null) {
                    stats = module.new SwitchStats();
                }

                StringBuilder r = new StringBuilder();
                r.append("{\"dpid\":\"").append(module.esc(dpid)).append("\",");
                r.append("\"packet_count\":").append(stats.packetCount).append(",");
                r.append("\"port_count\":").append(stats.ports.size()).append(",");
                r.append("\"uptime\":").append(System.currentTimeMillis() - stats.startTime).append("}");

                return r.toString();

            } catch (Exception e) {
                return "{\"error\":\"" + e.getMessage() + "\"}";
            }
        }
    }


    // ===== RESOURCE 4: GET /wm/packetin/flows =====
    public static class FlowsResource extends ServerResource {
        @Get("json")
        public String retrieve() {
            try {
                PacketInRestAPI module = instance;

                Map<String, FlowRecord> flows = module.getActiveFlows();

                return "{\"total_flows\":" + flows.size() + ", \"flows\":[]}";

            } catch (Exception e) {
                return "{\"error\":\"" + e.getMessage() + "\"}";
            }
        }
    }


    // ===== RESOURCE 5: GET /wm/packetin/anomalies =====
    public static class AnomaliesResource extends ServerResource {
        @Get("json")
        public String retrieve() {
            try {
                PacketInRestAPI module = instance;

                int critical = 0, warning = 0;
                for (AnomalyAlert a : module.anomalyAlerts.values()) {
                    if (a.severity > 80) critical++;
                    else if (a.severity > 40) warning++;
                }

                return "{\"total_anomalies\":" + module.anomalyAlerts.size()
                        + ",\"critical_count\":" + critical
                        + ",\"warning_count\":" + warning
                        + ",\"anomalies\":[]}";

            } catch (Exception e) {
                return "{\"error\":\"" + e.getMessage() + "\"}";
            }
        }
    }


    // ===== RESOURCE 6: POST /wm/packetin/reset =====
    public static class ResetResource extends ServerResource {
        @Post("json")
        public String reset(Representation entity) {
            try {
                PacketInRestAPI module = instance;

                module.globalStats.clear();
                module.switchStats.clear();
                module.anomalyAlerts.clear();
                module.startTime = System.currentTimeMillis();

                return "{\"status\":\"reset_successful\",\"timestamp\":" + System.currentTimeMillis() + "}";

            } catch (Exception e) {
                return "{\"error\":\"" + e.getMessage() + "\"}";
            }
        }
    }


    // ===== RESOURCE 7: GET /wm/packetin/test =====
    public static class TestPacketInResource extends ServerResource {
        @Get("json")
        public String test() {
            try {
                PacketInRestAPI module = instance;

                long total = 0;
                for (PacketInStats s : module.globalStats.values()) {
                    total += s.count;
                }

                return "{\"status\":\"online\",\"module\":\"PacketInRestAPI\",\"version\":\"1.0\","
                        + "\"total_packets\":" + total + ","
                        + "\"switches\":" + module.switchStats.size() + ","
                        + "\"anomalies\":" + module.anomalyAlerts.size() + "}";

            } catch (Exception e) {
                return "{\"error\":\"" + e.getMessage() + "\"}";
            }
        }
    }



    /* ============================================================
     * INNER MODEL CLASSES
     * ============================================================ */

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


    protected Map<String, FlowRecord> getActiveFlows() {
        return new ConcurrentHashMap<String, FlowRecord>();
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
