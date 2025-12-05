#!/usr/bin/env python3
"""
Script para configurar flujos OpenFlow en SW1, SW3 y SW4 para permitir comunicación
entre un host y el servidor de management (portal cautivo).

Hosts:
  - Host cliente: IP configurable, conectado a SW3 por puerto configurable
  - Management: 192.168.200.13 conectado a SW4 por el puerto 5

Conexión entre switches:
  - SW3 puerto 1 <-> SW1 puerto 3
  - SW1 puerto 4 <-> SW4 puerto 1

Protocolos permitidos:
  - ARP (resolución de direcciones MAC) - NOTA: Debe agregarse manualmente con ovs-ofctl
  - UDP (todos los puertos UDP)
  - TCP (todos los puertos TCP)

NOTA IMPORTANTE SOBRE ARP:
  Floodlight no soporta la acción NORMAL a través de su API REST. Para agregar
  el flujo ARP con actions=NORMAL, ejecuta manualmente en cada switch:
  
  sudo ovs-ofctl -O OpenFlow13 add-flow sw1 "priority=500,arp,actions=NORMAL"
  sudo ovs-ofctl -O OpenFlow13 add-flow sw3 "priority=500,arp,actions=NORMAL"
  sudo ovs-ofctl -O OpenFlow13 add-flow sw4 "priority=500,arp,actions=NORMAL"

NOTA: Todos los flujos se crean en la tabla 1.

Autor: Script generado para configuración de red SDN
Fecha: 2024
"""

import requests
import json
import sys
import time
from typing import Dict, List, Optional


class FloodlightController:
    """Clase para interactuar con la API REST de Floodlight"""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        """
        Inicializa la conexión al controlador Floodlight
        
        Args:
            host: Dirección IP del controlador (default: 127.0.0.1)
            port: Puerto del controlador (default: 8080)
        """
        self.base_url = f"http://{host}:{port}"
        self.headers = {'Content-Type': 'application/json'}
        
    def get_switches(self) -> List[Dict]:
        """
        Obtiene la lista de switches conectados al controlador
        
        Returns:
            Lista de diccionarios con información de los switches
        """
        try:
            url = f"{self.base_url}/wm/core/controller/switches/json"
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException:
            return []
    
    def get_switch_dpid_by_ip(self, ip_address: str) -> Optional[str]:
        """
        Obtiene el DPID de un switch por su dirección IP
        
        Args:
            ip_address: Dirección IP del switch (ej: "192.168.200.147")
            
        Returns:
            DPID del switch en formato string o None si no se encuentra
        """
        switches = self.get_switches()
        
        def search_ip_in_dict(data, target_ip):
            """Función recursiva para buscar IP en cualquier parte del diccionario"""
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, str) and target_ip in value:
                        return True
                    elif isinstance(value, (dict, list)):
                        if search_ip_in_dict(value, target_ip):
                            return True
            elif isinstance(data, list):
                for item in data:
                    if search_ip_in_dict(item, target_ip):
                        return True
            return False
        
        for switch in switches:
            # Buscar la IP en toda la estructura del switch
            if search_ip_in_dict(switch, ip_address):
                return switch.get('switchDPID')
            
            # También buscar directamente en campos comunes
            inet_address = switch.get('inetAddress', '')
            if isinstance(inet_address, str) and ip_address in inet_address:
                return switch.get('switchDPID')
            
            # Buscar en connectedSince o otros campos que puedan contener IPs
            for key in ['inetAddress', 'connectedSince', 'remoteInetAddress', 'localInetAddress']:
                value = switch.get(key, '')
                if isinstance(value, str) and ip_address in value:
                    return switch.get('switchDPID')
        
        return None
    
    def add_flow(self, flow: Dict) -> bool:
        """
        Añade un flujo estático al controlador
        
        Args:
            flow: Diccionario con la definición del flujo
            
        Returns:
            True si se añadió correctamente, False en caso contrario
        """
        try:
            # Endpoint correcto para Floodlight 1.2: /wm/staticflowpusher/json (sin "entry")
            url = f"{self.base_url}/wm/staticflowpusher/json"
            
            # Asegurar que el formato sea correcto para Floodlight 1.2
            # Agregar cookie y active si no están presentes
            flow_copy = flow.copy()
            if 'cookie' not in flow_copy:
                flow_copy['cookie'] = '0'
            if 'active' not in flow_copy:
                flow_copy['active'] = 'true'
            
            # Enviar el flujo
            response = requests.post(url, data=json.dumps(flow_copy), 
                                    headers=self.headers, timeout=5)
            
            if response.status_code == 200:
                # Verificar la respuesta JSON para confirmar éxito
                try:
                    result = response.json()
                    if result.get('status') == 'Entry pushed':
                        return True
                    elif result.get('status') == 'success':
                        return True
                    # Algunas versiones solo retornan 200 sin JSON
                    elif response.status_code == 200:
                        return True
                except (ValueError, KeyError):
                    # Si no hay JSON pero el código es 200, asumir éxito
                    if response.status_code == 200:
                        return True
                
            print(f"Error HTTP {response.status_code}: {response.text}")
            return False
                
        except requests.exceptions.RequestException as e:
            print(f"Error al añadir flujo {flow.get('name', 'unknown')}: {e}")
            return False
    
    def delete_all_flows(self, switch_dpid: str) -> bool:
        """
        Elimina todos los flujos estáticos de un switch
        
        Args:
            switch_dpid: DPID del switch
            
        Returns:
            True si se eliminaron correctamente, False en caso contrario
        """
        try:
            url = f"{self.base_url}/wm/staticflowpusher/clear/{switch_dpid}/json"
            response = requests.get(url, timeout=5)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False


def create_sw3_flows(switch_dpid: str, host_ip: str, host_port: str) -> List[Dict]:
    """
    Crea la lista de flujos para SW3 (host cliente)
    
    Args:
        switch_dpid: DPID del switch SW3
        host_ip: Dirección IP del host cliente
        host_port: Puerto del switch SW3 donde está conectado el host
        
    Returns:
        Lista de diccionarios con las definiciones de flujos
    """
    # Normalizar el puerto y la IP para nombres de flujos
    port_normalized = host_port.replace(':', '')
    ip_normalized = host_ip.replace('.', '_')
    
    flows = [
        # UDP: desde host hacia Management (192.168.200.13)
        {
            "switch": switch_dpid,
            "name": f"sw3_udp_{port_normalized}_to_1_{ip_normalized}",
            "table": "1",
            "priority": "200",
            "in_port": host_port,
            "eth_type": "0x0800",
            "ip_proto": "17",
            "ipv4_src": host_ip,
            "ipv4_dst": "192.168.200.13",
            "actions": "output=1"
        },
        # UDP: desde Management (192.168.200.13) hacia host
        {
            "switch": switch_dpid,
            "name": f"sw3_udp_1_to_{port_normalized}_{ip_normalized}",
            "table": "1",
            "priority": "200",
            "in_port": "1",
            "eth_type": "0x0800",
            "ip_proto": "17",
            "ipv4_src": "192.168.200.13",
            "ipv4_dst": host_ip,
            "actions": f"output={host_port}"
        },
        # TCP: todo tráfico TCP desde puerto del host hacia puerto 1 (sw1)
        {
            "switch": switch_dpid,
            "name": f"sw3_tcp_{port_normalized}_to_1_{ip_normalized}",
            "table": "1",
            "priority": "200",
            "in_port": host_port,
            "eth_type": "0x0800",
            "ip_proto": "6",
            "actions": "output=1"
        },
        # TCP: todo tráfico TCP desde puerto 1 (sw1) hacia puerto del host
        {
            "switch": switch_dpid,
            "name": f"sw3_tcp_1_to_{port_normalized}_{ip_normalized}",
            "table": "1",
            "priority": "200",
            "in_port": "1",
            "eth_type": "0x0800",
            "ip_proto": "6",
            "actions": f"output={host_port}"
        }
    ]
    return flows


def create_sw4_flows(switch_dpid: str, host_ip: str) -> List[Dict]:
    """
    Crea la lista de flujos para SW4 (servidor de management: 192.168.200.13)
    
    Args:
        switch_dpid: DPID del switch SW4
        host_ip: Dirección IP del host cliente
        
    Returns:
        Lista de diccionarios con las definiciones de flujos
    """
    # Normalizar la IP para nombres de flujos
    ip_normalized = host_ip.replace('.', '_')
    
    flows = [
        # UDP: desde Management (192.168.200.13) hacia host
        {
            "switch": switch_dpid,
            "name": f"sw4_udp_5_to_1_{ip_normalized}",
            "table": "1",
            "priority": "200",
            "in_port": "5",
            "eth_type": "0x0800",
            "ip_proto": "17",
            "ipv4_src": "192.168.200.13",
            "ipv4_dst": host_ip,
            "actions": "output=1"
        },
        # UDP: desde host hacia Management (192.168.200.13)
        {
            "switch": switch_dpid,
            "name": f"sw4_udp_1_to_5_{ip_normalized}",
            "table": "1",
            "priority": "200",
            "in_port": "1",
            "eth_type": "0x0800",
            "ip_proto": "17",
            "ipv4_src": host_ip,
            "ipv4_dst": "192.168.200.13",
            "actions": "output=5"
        },
        # TCP: todo tráfico TCP desde puerto 5 (management) hacia puerto 1 (sw1)
        {
            "switch": switch_dpid,
            "name": f"sw4_tcp_5_to_1_{ip_normalized}",
            "table": "1",
            "priority": "200",
            "in_port": "5",
            "eth_type": "0x0800",
            "ip_proto": "6",
            "actions": "output=1"
        },
        # TCP: todo tráfico TCP desde puerto 1 (sw1) hacia puerto 5 (management)
        {
            "switch": switch_dpid,
            "name": f"sw4_tcp_1_to_5_{ip_normalized}",
            "table": "1",
            "priority": "200",
            "in_port": "1",
            "eth_type": "0x0800",
            "ip_proto": "6",
            "actions": "output=5"
        }
    ]
    return flows


def create_sw1_flows(switch_dpid: str, host_ip: str) -> List[Dict]:
    """
    Crea la lista de flujos para SW1 (switch intermedio entre SW3 y SW4)
    
    Args:
        switch_dpid: DPID del switch SW1
        host_ip: Dirección IP del host cliente
        
    Returns:
        Lista de diccionarios con las definiciones de flujos
    """
    # Normalizar la IP para nombres de flujos
    ip_normalized = host_ip.replace('.', '_')
    
    flows = [
        # UDP: desde host hacia Management (192.168.200.13)
        {
            "switch": switch_dpid,
            "name": f"sw1_udp_3_to_4_{ip_normalized}",
            "table": "1",
            "priority": "200",
            "in_port": "3",
            "eth_type": "0x0800",
            "ip_proto": "17",
            "ipv4_src": host_ip,
            "ipv4_dst": "192.168.200.13",
            "actions": "output=4"
        },
        # UDP: desde Management (192.168.200.13) hacia host
        {
            "switch": switch_dpid,
            "name": f"sw1_udp_4_to_3_{ip_normalized}",
            "table": "1",
            "priority": "200",
            "in_port": "4",
            "eth_type": "0x0800",
            "ip_proto": "17",
            "ipv4_src": "192.168.200.13",
            "ipv4_dst": host_ip,
            "actions": "output=3"
        },
        # TCP: todo tráfico TCP desde puerto 3 (sw3) hacia puerto 4 (sw4)
        {
            "switch": switch_dpid,
            "name": f"sw1_tcp_3_to_4_{ip_normalized}",
            "table": "1",
            "priority": "200",
            "in_port": "3",
            "eth_type": "0x0800",
            "ip_proto": "6",
            "actions": "output=4"
        },
        # TCP: todo tráfico TCP desde puerto 4 (sw4) hacia puerto 3 (sw3)
        {
            "switch": switch_dpid,
            "name": f"sw1_tcp_4_to_3_{ip_normalized}",
            "table": "1",
            "priority": "200",
            "in_port": "4",
            "eth_type": "0x0800",
            "ip_proto": "6",
            "actions": "output=3"
        }
    ]
    return flows


def main():
    """Función principal del script"""
    print("=" * 60)
    print("Configurador de Flujos OpenFlow 1.3 para Host/Management")
    print("=" * 60)
    
    # Inicializar conexión al controlador
    controller = FloodlightController(host="127.0.0.1", port=8080)
    
    # Verificar conectividad
    print("\n[1] Verificando conectividad con el controlador...")
    switches = controller.get_switches()
    if not switches:
        print("ERROR: No se pudo conectar al controlador o no hay switches conectados.")
        print("Asegúrate de que:")
        print("  - El túnel SSH esté activo: ssh -L 8080:192.168.201.200:8080 ubuntu@10.20.12.110")
        print("  - El controlador Floodlight esté ejecutándose")
        print("  - Los switches estén conectados al controlador")
        sys.exit(1)
    
    print(f"✓ Controlador conectado. Switches encontrados: {len(switches)}")
    for switch in switches:
        dpid = switch.get('switchDPID', 'N/A')
        name = switch.get('switchName', 'N/A')
        print(f"  - {name} (DPID: {dpid})")
    
    # Obtener DPIDs de SW1, SW3 y SW4 por IP
    print("\n[2] Obteniendo identificadores de switches por IP...")
    
    # Mapeo de IPs de los switches (no de los hosts)
    switch_ips = {
        "sw1": "192.168.200.145",
        "sw3": "192.168.200.147",
        "sw4": "192.168.200.148"
    }
    
    sw1_dpid = controller.get_switch_dpid_by_ip(switch_ips["sw1"])
    sw3_dpid = controller.get_switch_dpid_by_ip(switch_ips["sw3"])
    sw4_dpid = controller.get_switch_dpid_by_ip(switch_ips["sw4"])
    
    # Si no se encontraron por IP, permitir selección manual
    if not sw1_dpid or not sw3_dpid or not sw4_dpid:
        print("\n⚠ No se pudieron identificar automáticamente los switches por IP.")
        print("Switches disponibles:")
        for i, switch in enumerate(switches, 1):
            dpid = switch.get('switchDPID', 'N/A')
            name = switch.get('switchName', 'N/A')
            inet = switch.get('inetAddress', 'N/A')
            print(f"  [{i}] {name} - IP: {inet} - DPID: {dpid}")
        
        if not sw1_dpid:
            try:
                choice = input("\n¿Cuál es sw1 (intermedio - IP switch: 192.168.200.145)? [1-4]: ").strip()
                idx = int(choice) - 1
                if 0 <= idx < len(switches):
                    sw1_dpid = switches[idx].get('switchDPID')
                    print(f"✓ sw1 seleccionado: {sw1_dpid}")
                else:
                    print("ERROR: Selección inválida")
                    sys.exit(1)
            except (ValueError, KeyboardInterrupt):
                print("\nOperación cancelada")
                sys.exit(1)
        
        if not sw3_dpid:
            try:
                choice = input("\n¿Cuál es sw3 (host - IP switch: 192.168.200.147)? [1-4]: ").strip()
                idx = int(choice) - 1
                if 0 <= idx < len(switches):
                    sw3_dpid = switches[idx].get('switchDPID')
                    print(f"✓ sw3 seleccionado: {sw3_dpid}")
                else:
                    print("ERROR: Selección inválida")
                    sys.exit(1)
            except (ValueError, KeyboardInterrupt):
                print("\nOperación cancelada")
                sys.exit(1)
        
        if not sw4_dpid:
            try:
                choice = input("¿Cuál es sw4 (Management - IP switch: 192.168.200.148)? [1-4]: ").strip()
                idx = int(choice) - 1
                if 0 <= idx < len(switches):
                    sw4_dpid = switches[idx].get('switchDPID')
                    print(f"✓ sw4 seleccionado: {sw4_dpid}")
                else:
                    print("ERROR: Selección inválida")
                    sys.exit(1)
            except (ValueError, KeyboardInterrupt):
                print("\nOperación cancelada")
                sys.exit(1)
    else:
        print(f"✓ sw1 encontrado por IP {switch_ips['sw1']}: {sw1_dpid}")
        print(f"✓ sw3 encontrado por IP {switch_ips['sw3']}: {sw3_dpid}")
        print(f"✓ sw4 encontrado por IP {switch_ips['sw4']}: {sw4_dpid}")
    
    # Solicitar información del host
    print("\n[3] Configuración del host cliente...")
    try:
        host_ip = input("Ingresa la IP del host cliente (ej: 192.168.200.21): ").strip()
        if not host_ip:
            print("ERROR: La IP del host es requerida")
            sys.exit(1)
        
        host_port = input("Ingresa el puerto de SW3 donde está conectado el host (ej: 4): ").strip()
        if not host_port:
            print("ERROR: El puerto del host es requerido")
            sys.exit(1)
        
        print(f"✓ Host configurado: {host_ip} en SW3 puerto {host_port}")
    except KeyboardInterrupt:
        print("\nOperación cancelada")
        sys.exit(1)
    
    # Crear definiciones de flujos
    print("\n[4] Creando definiciones de flujos...")
    print(f"  Host cliente: {host_ip} (SW3 puerto {host_port})")
    print("  Servidor Management: 192.168.200.13 (SW4 puerto 5)")
    print("  Conexión: SW3 puerto 1 <-> SW1 puerto 3")
    print("  Conexión: SW1 puerto 4 <-> SW4 puerto 1")
    print("  Tabla: 1 (todos los flujos)")
    flows_sw1 = create_sw1_flows(sw1_dpid, host_ip)
    flows_sw3 = create_sw3_flows(sw3_dpid, host_ip, host_port)
    flows_sw4 = create_sw4_flows(sw4_dpid, host_ip)
    print(f"✓ {len(flows_sw1)} flujos para sw1")
    print(f"✓ {len(flows_sw3)} flujos para sw3")
    print(f"✓ {len(flows_sw4)} flujos para sw4")
    
    # Eliminar flujos existentes (deshabilitado - no se eliminan flujos anteriores)
    # print("\n[3.5] Eliminando flujos existentes...")
    # print("  Eliminando flujos de sw1...")
    # controller.delete_all_flows(sw1_dpid)
    # print("  Eliminando flujos de sw3...")
    # controller.delete_all_flows(sw3_dpid)
    # print("  Eliminando flujos de sw4...")
    # controller.delete_all_flows(sw4_dpid)
    # print("  ✓ Flujos antiguos eliminados")
    # time.sleep(1)  # Esperar un momento para que se procesen las eliminaciones
    
    # Instalar flujos en SW1
    print("\n[5] Instalando flujos en sw1...")
    success_sw1 = 0
    for flow in flows_sw1:
        if controller.add_flow(flow):
            print(f"  ✓ {flow['name']}")
            success_sw1 += 1
        else:
            print(f"  ✗ {flow['name']} - ERROR")
    
    # Instalar flujos en SW3
    print("\n[6] Instalando flujos en sw3...")
    success_sw3 = 0
    for flow in flows_sw3:
        if controller.add_flow(flow):
            print(f"  ✓ {flow['name']}")
            success_sw3 += 1
        else:
            print(f"  ✗ {flow['name']} - ERROR")
    
    # Instalar flujos en SW4
    print("\n[7] Instalando flujos en sw4...")
    success_sw4 = 0
    for flow in flows_sw4:
        if controller.add_flow(flow):
            print(f"  ✓ {flow['name']}")
            success_sw4 += 1
        else:
            print(f"  ✗ {flow['name']} - ERROR")
    
    # Resumen
    print("\n" + "=" * 60)
    print("RESUMEN")
    print("=" * 60)
    print(f"sw1: {success_sw1}/{len(flows_sw1)} flujos instalados")
    print(f"sw3: {success_sw3}/{len(flows_sw3)} flujos instalados")
    print(f"sw4: {success_sw4}/{len(flows_sw4)} flujos instalados")
    
    if success_sw1 == len(flows_sw1) and success_sw3 == len(flows_sw3) and success_sw4 == len(flows_sw4):
        print("\n✓ Todos los flujos se instalaron correctamente!")
        return 0
    else:
        print("\n⚠ Algunos flujos no se pudieron instalar. Revisa los errores arriba.")
        return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nOperación cancelada por el usuario.")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR INESPERADO: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

