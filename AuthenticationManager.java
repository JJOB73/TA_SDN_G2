package net.floodlightcontroller.pucp;

import java.util.*;
import java.util.concurrent.*;

import org.restlet.resource.ServerResource;
import org.restlet.resource.Post;
import org.restlet.resource.Get;
import org.restlet.representation.Representation;
import org.restlet.routing.Router;
import org.restlet.Context;

import net.floodlightcontroller.core.module.*;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.restserver.RestletRoutable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class AuthenticationManager implements IFloodlightModule, RestletRoutable {

    protected static Logger log = LoggerFactory.getLogger(AuthenticationManager.class);

    protected IRestApiService restApi;

    // Almacenamiento de sesiones activas
    private ConcurrentHashMap<String, SessionInfo> activeSessions;

    // Control de intentos fallidos (MAC → contador)
    private ConcurrentHashMap<String, FailureRecord> failureTracker;

    // MACs bloqueadas (MAC → timestamp de desbloqueo)
    private ConcurrentHashMap<String, Long> blockedMACs;

    // Configuración RADIUS
    private static final String RADIUS_SERVER = "192.168.200.12";
    private static final int RADIUS_PORT = 1812;
    private static final String RADIUS_SECRET = "PUCP_Secret_2024";

    // Límites de seguridad
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long BLOCK_DURATION = 900000; // 15 minutos

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        log.info("[AUTH] Initializing AuthenticationManager");

        try {
            restApi = context.getServiceImpl(IRestApiService.class);
        } catch (Exception e) {
            log.error("[AUTH] Error getting REST service: {}", e.getMessage());
            throw new FloodlightModuleException(e);
        }

        activeSessions = new ConcurrentHashMap<String, SessionInfo>();
        failureTracker = new ConcurrentHashMap<String, FailureRecord>();
        blockedMACs = new ConcurrentHashMap<String, Long>();
    }

    @Override
    public void startUp(FloodlightModuleContext context) {
        log.info("[AUTH] Starting AuthenticationManager");

        restApi.addRestletRoutable(this);
        startCleanupThread();

        log.info("[AUTH] AuthenticationManager started - REST API active");
    }


    @Override
    public org.restlet.Restlet getRestlet(Context context) {
        Router router = new Router(context);

        router.attach("/validate-credentials", ValidateCredentialsResource.class);
        router.attach("/sessions", SessionsResource.class);
        router.attach("/logout", LogoutResource.class);
        router.attach("/status", StatusResource.class);

        return router;
    }

    @Override
    public String basePath() {
        return "/wm/auth";
    }

    // =========================================================================
    // RESOURCE 1: POST /wm/auth/validate-credentials
    // Valida credenciales y retorna sesión
    // =========================================================================

    public class ValidateCredentialsResource extends ServerResource {

        @Post("json")
        public String validateCredentials(Representation entity) {
            try {
                String jsonString = entity.getText();
                
                // Parse manual JSON (sin dependencia org.json)
                String username = extractJsonValue(jsonString, "username");
                String password = extractJsonValue(jsonString, "password");
                String macAddress = extractJsonValue(jsonString, "mac");

                long startTime = System.currentTimeMillis();

                // 1. VALIDACIÓN DE ENTRADA
                if (!isValidUsername(username) || !isValidPassword(password)) {
                    recordFailedAttempt(macAddress);
                    return buildJsonResponse("invalid_format", 400, "Invalid username or password format");
                }

                // 2. VERIFICAR SI MAC ESTÁ BLOQUEADA
                if (isBlocked(macAddress)) {
                    long remainingTime = getRemainingBlockTime(macAddress);
                    return buildJsonResponse("blocked", 403, "too_many_attempts", 
                        "retry_after_seconds", String.valueOf(remainingTime / 1000));
                }

                // 3. AUTENTICACIÓN RADIUS 
                boolean authenticated = authenticateRadius(username, password);

                if (!authenticated) {
                    recordFailedAttempt(macAddress);

                    if (getFailureCount(macAddress) >= MAX_FAILED_ATTEMPTS) {
                        blockMAC(macAddress, BLOCK_DURATION);
                        return buildJsonResponse("blocked", 403, "too_many_attempts",
                            "retry_after_seconds", String.valueOf(BLOCK_DURATION / 1000));
                    }

                    return buildJsonResponse("unauthorized", 401, "Invalid credentials",
                        "attempts_remaining", String.valueOf(MAX_FAILED_ATTEMPTS - getFailureCount(macAddress)));
                }

                // 4. OBTENER ROL (simulado)
                String role = getUserRole(username);

                // 5. CREAR SESIÓN
                SessionInfo session = createSession(username, macAddress, role);

                // 6. LIMPIAR INTENTOS FALLIDOS
                clearFailedAttempts(macAddress);

                long duration = System.currentTimeMillis() - startTime;

                log.info("[AUTH] Authentication successful: user={}, role={}, duration={}ms", 
                    new Object[]{username, role, Long.valueOf(duration)});

                // 7. RESPUESTA EXITOSA
                String response = "{" +
                    "\"status\":\"authenticated\"," +
                    "\"code\":200," +
                    "\"session_id\":\"" + escapeJson(session.getSessionId()) + "\"," +
                    "\"role\":\"" + role + "\"," +
                    "\"username\":\"" + escapeJson(username) + "\"," +
                    "\"mac_address\":\"" + macAddress + "\"," +
                    "\"auth_duration_ms\":" + duration + "," +
                    "\"timestamp\":" + System.currentTimeMillis() + "," +
                    "\"session_expires\":" + session.getExpirationTime() +
                    "}";

                return response;

            } catch (Exception e) {
                log.error("[AUTH] Error: {}", e.getMessage());
                return buildJsonResponse("error", 500, e.getMessage());
            }
        }
    }

    // =========================================================================
    // RESOURCE 2: GET /wm/auth/sessions
    // Lista sesiones activas
    // =========================================================================

    public class SessionsResource extends ServerResource {

        @Get("json")
        public String getSessions() {
            try {
                StringBuilder sb = new StringBuilder();
                sb.append("{\"sessions\":[");
                
                int count = 0;
                for (SessionInfo session : activeSessions.values()) {
                    if (count > 0) sb.append(",");
                    sb.append("{");
                    sb.append("\"session_id\":\"").append(escapeJson(session.getSessionId())).append("\",");
                    sb.append("\"username\":\"").append(escapeJson(session.getUsername())).append("\",");
                    sb.append("\"mac_address\":\"").append(session.getMacAddress()).append("\",");
                    sb.append("\"role\":\"").append(session.getRole()).append("\",");
                    sb.append("\"created_at\":").append(session.getCreatedTime()).append(",");
                    sb.append("\"expires_at\":").append(session.getExpirationTime()).append(",");
                    sb.append("\"is_active\":").append(session.isActive());
                    sb.append("}");
                    count++;
                }
                
                sb.append("],\"total_sessions\":").append(activeSessions.size());
                sb.append(",\"timestamp\":").append(System.currentTimeMillis()).append("}");

                return sb.toString();

            } catch (Exception e) {
                log.error("[AUTH] Error retrieving sessions: {}", e.getMessage());
                return "{\"error\":\"" + escapeJson(e.getMessage()) + "\"}";
            }
        }
    }

    // =========================================================================
    // RESOURCE 3: POST /wm/auth/logout
    // Cerrar sesión
    // =========================================================================

    public class LogoutResource extends ServerResource {

        @Post("json")
        public String logout(Representation entity) {
            try {
                String jsonString = entity.getText();
                String macAddress = extractJsonValue(jsonString, "mac");

                SessionInfo session = activeSessions.remove(macAddress);

                if (session != null) {
                    log.info("[AUTH] Logout successful: user={}, mac={}", 
                        session.getUsername(), macAddress);
                    return buildJsonResponse("logged_out", 200, "Session terminated successfully");
                } else {
                    return buildJsonResponse("not_found", 404, "No active session found");
                }

            } catch (Exception e) {
                log.error("[AUTH] Logout error: {}", e.getMessage());
                return buildJsonResponse("error", 500, e.getMessage());
            }
        }
    }

    // =========================================================================
    // RESOURCE 4: GET /wm/auth/status
    // Estado del módulo
    // =========================================================================

    public class StatusResource extends ServerResource {

        @Get("json")
        public String represent() {
            try {
                String response = "{" +
                    "\"status\":\"active\"," +
                    "\"active_sessions\":" + activeSessions.size() + "," +
                    "\"blocked_macs\":" + blockedMACs.size() + "," +
                    "\"tracked_failures\":" + failureTracker.size() + "," +
                    "\"radius_server\":\"" + RADIUS_SERVER + ":" + RADIUS_PORT + "\"," +
                    "\"timestamp\":" + System.currentTimeMillis() +
                    "}";
                return response;

            } catch (Exception e) {
                return "{\"error\":\"" + escapeJson(e.getMessage()) + "\"}";
            }
        }
    }

    // =========================================================================
    // MÉTODOS AUXILIARES
    // =========================================================================

    /**
     * Extraer valor JSON manualmente 
     */
    private String extractJsonValue(String json, String key) {
        String pattern = "\"" + key + "\":\"";
        int start = json.indexOf(pattern);
        if (start == -1) return "";
        
        start += pattern.length();
        int end = json.indexOf("\"", start);
        if (end == -1) return "";
        
        return json.substring(start, end);
    }

    /**
     * Escapar caracteres especiales en JSON
     */
    private String escapeJson(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\")
                   .replace("\"", "\\\"")
                   .replace("\n", "\\n")
                   .replace("\r", "\\r")
                   .replace("\t", "\\t");
    }

    /**
     * Construir respuesta JSON simple
     */
    private String buildJsonResponse(String status, int code, String message) {
        return "{\"status\":\"" + status + "\",\"code\":" + code + 
               ",\"message\":\"" + escapeJson(message) + "\"}";
    }

    /**
     * Construir respuesta JSON con parámetros extra
     */
    private String buildJsonResponse(String status, int code, String key1, String key2, String value2) {
        return "{\"status\":\"" + status + "\",\"code\":" + code + 
               ",\"" + key2 + "\":" + value2 + "}";
    }

    /**
     * Autenticación RADIUS 
     */
    private boolean authenticateRadius(String username, String password) {
        try {
            log.info("[AUTH] RADIUS authentication for user: {}", username);

            // SIMULACIÓN TEMPORAL
            if (username.equals("estudiante1") && password.equals("estudiante123")) return true;
            if (username.equals("profesor1") && password.equals("profesor123")) return true;
            if (username.equals("admin1") && password.equals("admin123")) return true;

            return false;

        } catch (Exception e) {
            log.error("[AUTH] RADIUS error: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Obtener rol del usuario
     */
    private String getUserRole(String username) {
        if (username.startsWith("estudiante")) return "student";
        if (username.startsWith("profesor")) return "professor";
        if (username.startsWith("admin")) return "admin";
        if (username.startsWith("staff")) return "staff";
        return "guest";
    }

    /**
     * Crear nueva sesión
     */
    private SessionInfo createSession(String username, String macAddress, String role) {
        String sessionId = UUID.randomUUID().toString();
        long now = System.currentTimeMillis();
        long expiration = now + (4 * 3600 * 1000); // 4 horas

        SessionInfo session = new SessionInfo(
            sessionId, username, macAddress, role, now, expiration
        );

        activeSessions.put(macAddress, session);

        return session;
    }

    /**
     * Validaciones
     */
    private boolean isValidUsername(String username) {
        if (username == null || username.isEmpty()) return false;
        if (username.length() < 3 || username.length() > 50) return false;
        return username.matches("^[a-zA-Z0-9._-]+$");
    }

    private boolean isValidPassword(String password) {
        if (password == null || password.isEmpty()) return false;
        return password.length() >= 6;
    }

    /**
     * Gestión de intentos fallidos
     */
    private void recordFailedAttempt(String macAddress) {
        FailureRecord record = failureTracker.get(macAddress);
        if (record == null) {
            record = new FailureRecord();
            failureTracker.put(macAddress, record);
        }
        record.increment();

        log.warn("[AUTH] Failed attempt from MAC: {} (count: {})", 
            macAddress, Integer.valueOf(record.getCount()));
    }

    private int getFailureCount(String macAddress) {
        FailureRecord record = failureTracker.get(macAddress);
        return (record != null) ? record.getCount() : 0;
    }

    private void clearFailedAttempts(String macAddress) {
        failureTracker.remove(macAddress);
    }

    /**
     * Gestión de bloqueos
     */
    private void blockMAC(String macAddress, long duration) {
        long unblockTime = System.currentTimeMillis() + duration;
        blockedMACs.put(macAddress, Long.valueOf(unblockTime));
        log.warn("[AUTH] MAC blocked: {} until {} minutes", 
            macAddress, Long.valueOf(duration / 60000));
    }

    private boolean isBlocked(String macAddress) {
        Long unblockTime = blockedMACs.get(macAddress);
        if (unblockTime == null) return false;

        if (System.currentTimeMillis() < unblockTime.longValue()) {
            return true;
        } else {
            blockedMACs.remove(macAddress);
            return false;
        }
    }

    private long getRemainingBlockTime(String macAddress) {
        Long unblockTime = blockedMACs.get(macAddress);
        if (unblockTime == null) return 0;
        return Math.max(0, unblockTime.longValue() - System.currentTimeMillis());
    }

    /**
     * Thread de limpieza periódica - SIN LAMBDAS (Java 7 compatible)
     */
    private void startCleanupThread() {
        Thread cleanupThread = new Thread(new Runnable() {
            @Override
            public void run() {
                while (true) {
                    try {
                        Thread.sleep(60000); // Cada minuto

                        long now = System.currentTimeMillis();

                        // Limpiar sesiones expiradas
                        Iterator<Map.Entry<String, SessionInfo>> sessIter = 
                            activeSessions.entrySet().iterator();
                        while (sessIter.hasNext()) {
                            Map.Entry<String, SessionInfo> entry = sessIter.next();
                            if (entry.getValue().getExpirationTime() < now) {
                                sessIter.remove();
                            }
                        }

                        // Limpiar bloqueos vencidos
                        Iterator<Map.Entry<String, Long>> blockIter = 
                            blockedMACs.entrySet().iterator();
                        while (blockIter.hasNext()) {
                            Map.Entry<String, Long> entry = blockIter.next();
                            if (entry.getValue().longValue() < now) {
                                blockIter.remove();
                            }
                        }

                        // Limpiar registros de fallos antiguos (>1 hora)
                        long oneHourAgo = now - 3600000;
                        Iterator<Map.Entry<String, FailureRecord>> failIter = 
                            failureTracker.entrySet().iterator();
                        while (failIter.hasNext()) {
                            Map.Entry<String, FailureRecord> entry = failIter.next();
                            if (entry.getValue().getLastAttempt() < oneHourAgo) {
                                failIter.remove();
                            }
                        }

                    } catch (InterruptedException e) {
                        log.error("[AUTH] Cleanup thread interrupted");
                        break;
                    }
                }
            }
        });
        cleanupThread.setDaemon(true);
        cleanupThread.setName("AuthCleanupThread");
        cleanupThread.start();
    }

    // =========================================================================
    // CLASES INTERNAS
    // =========================================================================

    /**
     * Información de sesión
     */
    public class SessionInfo {
        private String sessionId;
        private String username;
        private String macAddress;
        private String role;
        private long createdTime;
        private long expirationTime;

        public SessionInfo(String sessionId, String username, String macAddress,
                          String role, long createdTime, long expirationTime) {
            this.sessionId = sessionId;
            this.username = username;
            this.macAddress = macAddress;
            this.role = role;
            this.createdTime = createdTime;
            this.expirationTime = expirationTime;
        }

        public String getSessionId() { return sessionId; }
        public String getUsername() { return username; }
        public String getMacAddress() { return macAddress; }
        public String getRole() { return role; }
        public long getCreatedTime() { return createdTime; }
        public long getExpirationTime() { return expirationTime; }
        public boolean isActive() { return System.currentTimeMillis() < expirationTime; }
    }

    /**
     * Registro de intentos fallidos
     */
    private class FailureRecord {
        private int count = 0;
        private long lastAttempt = System.currentTimeMillis();

        public void increment() {
            count++;
            lastAttempt = System.currentTimeMillis();
        }

        public int getCount() { return count; }
        public long getLastAttempt() { return lastAttempt; }
    }

    // =========================================================================
    // INTERFAZ IFloodlightModule - IMPLEMENTACIÓN CORRECTA
    // =========================================================================

    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return Collections.emptyList();
    }

    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return Collections.emptyMap();
    }

    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l =
            new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IRestApiService.class);
        return l;
    }

    public String getName() {
        return "AuthenticationManager";
    }

    public boolean isCallbackOrderingPrereq(String type, String name) {
        return false;
    }

    public boolean isCallbackOrderingPostreq(String type, String name) {
        return false;
    }
}
