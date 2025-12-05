#!/usr/bin/env python3
"""
Script para configurar flujos DHCP basados en MAC addresses para conectar
hosts clientes DHCP al servidor de management.

Topología:
  - Hosts (clientes DHCP) conectados a SW3
  - SW3 puerto 1 → SW1 puerto 3
  - SW1 puerto 4 → SW4 puerto 1
  - SW4 puerto 5 → Servidor Management

Hosts clientes DHCP (por MAC y puerto en SW3):
  - h1: fa:16:3e:1f:a1:d4 → SW3 puerto 4
  - h2: fa:16:3e:4b:7d:ea → SW3 puerto 5
  - h3: fa:16:3e:50:27:7a → SW3 puerto 6

Flujos configurados:
  - Cliente → Servidor: MAC origen = MAC cliente, UDP src=68, dst=67
  - Servidor → Cliente: MAC destino = MAC cliente, UDP src=67, dst=68

Uso:
    python configurar_dhcp_mac.py                    # Controlador en localhost:8080
    python configurar_dhcp_mac.py 192.168.1.100      # Especificar host
    python configurar_dhcp_mac.py 192.168.1.100 8080 # Especificar host y puerto

Autor: Script generado para configuración de red SDN
Fecha: 2024
"""

import requests
import json
import sys
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
    
    def get_static_flows(self, switch_dpid: str) -> Dict:
        """
        Obtiene los flujos estáticos instalados en un switch
        
        Args:
            switch_dpid: DPID del switch
            
        Returns:
            Diccionario con los flujos estáticos o {} si hay error
        """
        try:
            url = f"{self.base_url}/wm/staticflowpusher/list/{switch_dpid}/json"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                return response.json()
            return {}
        except requests.exceptions.RequestException:
            return {}
    
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
            if ip_address in str(inet_address):
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
            # Endpoint correcto para Floodlight 1.2: /wm/staticflowpusher/json
            url = f"{self.base_url}/wm/staticflowpusher/json"
            
            # Asegurar que el formato sea correcto para Floodlight 1.2
            flow_copy = flow.copy()
            if 'cookie' not in flow_copy:
                flow_copy['cookie'] = '0'
            if 'active' not in flow_copy:
                flow_copy['active'] = 'true'
            
            # Enviar el flujo usando json= (formato del ejemplo)
            response = requests.post(url, json=flow_copy, timeout=5)
            
            # Siempre intentar parsear la respuesta JSON
            try:
                result = response.json()
            except (ValueError, KeyError):
                result = {}
            
            # Debug: mostrar respuesta para flujos DHCP (solo los primeros para no saturar)
            flow_name = flow.get('name', 'unknown')
            if 'dhcp' in flow_name.lower() and 'sw3_dhcp_fa163e1fa1d4_to_server' in flow_name:
                print(f"      [DEBUG] Respuesta para {flow_name}: {result}")
            
            # Verificar respuesta
            if response.status_code == 200:
                # Verificar si hay mensaje de error en la respuesta
                if 'status' in result:
                    if result.get('status') == 'Entry pushed':
                        return True
                    elif result.get('status') == 'success':
                        return True
                    elif 'Error' in result.get('status', '') or 'error' in str(result.get('status', '')).lower():
                        # Hay un error en el status
                        print(f"      Error en respuesta: {result}")
                        print(f"      Flujo fallido: {flow.get('name', 'unknown')}")
                        print(f"      JSON enviado: {json.dumps(flow_copy, indent=2)}")
                        return False
                
                # Si no hay status pero el código es 200, verificar si hay mensaje de error
                if 'message' in result or 'error' in result:
                    print(f"      Error en respuesta: {result}")
                    print(f"      Flujo fallido: {flow.get('name', 'unknown')}")
                    print(f"      JSON enviado: {json.dumps(flow_copy, indent=2)}")
                    return False
                
                # Si llegamos aquí y es 200 sin errores aparentes, asumir éxito
                return True
            else:
                # Mostrar error detallado
                print(f"      Error HTTP {response.status_code}")
                print(f"      Respuesta: {result if result else response.text}")
                print(f"      Flujo fallido: {flow.get('name', 'unknown')}")
                print(f"      JSON enviado: {json.dumps(flow_copy, indent=2)}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"      Excepción al agregar flujo {flow.get('name', 'unknown')}: {e}")
            return False


def create_sw3_flows(switch_dpid: str, client_mac: str, host_port: str) -> List[Dict]:
    """
    Crea los flujos DHCP para SW3 (donde están conectados los hosts clientes)
    
    Args:
        switch_dpid: DPID del switch SW3
        client_mac: MAC address del cliente DHCP
        host_port: Puerto de SW3 donde está conectado el host
        
    Returns:
        Lista de diccionarios con las definiciones de flujos
    """
    # Normalizar MAC para el nombre del flujo (sin : y en minúsculas)
    mac_normalized = client_mac.lower().replace(':', '')
    
    flows = [
        # Cliente → Servidor: desde el puerto del host hacia SW1 (puerto 1)
        {
            "switch": switch_dpid,
            "name": f"sw3_dhcp_{mac_normalized}_to_server",
            "table": "0",
            "priority": "500",
            "active": "true",
            "in_port": host_port,
            "eth_type": "0x0800",
            "ether_type": "0x800",
            "ip_proto": "17",
            "udp_src": "68",
            "udp_dst": "67",
            "eth_src": client_mac.lower(),
            "actions": "output=1"
        },
        # Servidor → Cliente: desde SW1 (puerto 1) hacia el host (puerto específico)
        {
            "switch": switch_dpid,
            "name": f"sw3_dhcp_{mac_normalized}_from_server",
            "table": "0",
            "priority": "500",
            "active": "true",
            "in_port": "1",
            "eth_type": "0x0800",
            "ether_type": "0x800",
            "ip_proto": "17",
            "udp_src": "67",
            "udp_dst": "68",
            "eth_dst": client_mac.lower(),
            "actions": f"output={host_port}"
        }
    ]
    return flows


def create_sw1_flows(switch_dpid: str, client_mac: str) -> List[Dict]:
    """
    Crea los flujos DHCP para SW1 (switch intermedio entre SW3 y SW4)
    
    Args:
        switch_dpid: DPID del switch SW1
        client_mac: MAC address del cliente DHCP
        
    Returns:
        Lista de diccionarios con las definiciones de flujos
    """
    # Normalizar MAC para el nombre del flujo
    mac_normalized = client_mac.lower().replace(':', '')
    
    flows = [
        # Cliente → Servidor: desde SW3 (puerto 3) hacia SW4 (puerto 4)
        {
            "switch": switch_dpid,
            "name": f"sw1_dhcp_{mac_normalized}_to_server",
            "table": "0",
            "priority": "500",
            "active": "true",
            "in_port": "3",
            "eth_type": "0x0800",
            "ether_type": "0x800",
            "ip_proto": "17",
            "udp_src": "68",
            "udp_dst": "67",
            "eth_src": client_mac.lower(),
            "actions": "output=4"
        },
        # Servidor → Cliente: desde SW4 (puerto 4) hacia SW3 (puerto 3)
        {
            "switch": switch_dpid,
            "name": f"sw1_dhcp_{mac_normalized}_from_server",
            "table": "0",
            "priority": "500",
            "active": "true",
            "in_port": "4",
            "eth_type": "0x0800",
            "ether_type": "0x800",
            "ip_proto": "17",
            "udp_src": "67",
            "udp_dst": "68",
            "eth_dst": client_mac.lower(),
            "actions": "output=3"
        }
    ]
    return flows


def create_sw4_flows(switch_dpid: str, client_mac: str) -> List[Dict]:
    """
    Crea los flujos DHCP para SW4 (donde está conectado el servidor)
    
    Args:
        switch_dpid: DPID del switch SW4
        client_mac: MAC address del cliente DHCP
        
    Returns:
        Lista de diccionarios con las definiciones de flujos
    """
    # Normalizar MAC para el nombre del flujo
    mac_normalized = client_mac.lower().replace(':', '')
    
    flows = [
        # Cliente → Servidor: desde SW1 (puerto 1) hacia servidor (puerto 5)
        {
            "switch": switch_dpid,
            "name": f"sw4_dhcp_{mac_normalized}_to_server",
            "table": "0",
            "priority": "500",
            "active": "true",
            "in_port": "1",
            "eth_type": "0x0800",
            "ether_type": "0x800",
            "ip_proto": "17",
            "udp_src": "68",
            "udp_dst": "67",
            "eth_src": client_mac.lower(),
            "actions": "output=5"
        },
        # Servidor → Cliente: desde servidor (puerto 5) hacia SW1 (puerto 1)
        {
            "switch": switch_dpid,
            "name": f"sw4_dhcp_{mac_normalized}_from_server",
            "table": "0",
            "priority": "500",
            "active": "true",
            "in_port": "5",
            "eth_type": "0x0800",
            "ether_type": "0x800",
            "ip_proto": "17",
            "udp_src": "67",
            "udp_dst": "68",
            "eth_dst": client_mac.lower(),
            "actions": "output=1"
        }
    ]
    return flows


def create_sw1_sw4_goto_table_flows(switch_dpid: str, switch_name: str, host_ips: List[str]) -> List[Dict]:
    """
    Crea flujos para SW1 y SW4 que redirigen tráfico IP de/hacia hosts a tabla 1
    
    Args:
        switch_dpid: DPID del switch
        switch_name: Nombre del switch (sw1 o sw4)
        host_ips: Lista de IPs de los hosts
        
    Returns:
        Lista de diccionarios con las definiciones de flujos
    """
    flows = []
    for host_ip in host_ips:
        ip_normalized = host_ip.replace('.', '_')
        
        # Flujo 1: tráfico con IP origen del host → goto_table:1
        flows.append({
            "switch": switch_dpid,
            "name": f"{switch_name}_goto_table1_src_{ip_normalized}",
            "table": "0",
            "priority": "200",
            "active": "true",
            "eth_type": "0x0800",
            "ether_type": "0x800",
            "ipv4_src": host_ip,
            "instruction_goto_table": "1"
        })
        
        # Flujo 2: tráfico con IP destino del host → goto_table:1
        flows.append({
            "switch": switch_dpid,
            "name": f"{switch_name}_goto_table1_dst_{ip_normalized}",
            "table": "0",
            "priority": "200",
            "active": "true",
            "eth_type": "0x0800",
            "ether_type": "0x800",
            "ipv4_dst": host_ip,
            "instruction_goto_table": "1"
        })
    
    return flows


def create_sw3_goto_table_flows(switch_dpid: str, host_config: Dict[str, Dict]) -> List[Dict]:
    """
    Crea flujos para SW3 que redirigen tráfico IP de/hacia hosts a tabla 1
    El flujo de origen también matchea el puerto de entrada
    
    Args:
        switch_dpid: DPID del switch SW3
        host_config: Diccionario con MAC como clave y {"port": "X", "ip": "Y.Y.Y.Y"} como valor
        
    Returns:
        Lista de diccionarios con las definiciones de flujos
    """
    flows = []
    
    # Mapeo de IPs a puertos (estático)
    ip_to_port = {
        "192.168.200.4": "4",
        "192.168.200.2": "5",
        "192.168.200.3": "6"
    }
    
    for host_ip, host_port in ip_to_port.items():
        ip_normalized = host_ip.replace('.', '_')
        
        # Flujo 1: tráfico con IP origen del host desde su puerto → goto_table:1
        flows.append({
            "switch": switch_dpid,
            "name": f"sw3_goto_table1_src_{ip_normalized}_port_{host_port}",
            "table": "0",
            "priority": "200",
            "active": "true",
            "in_port": host_port,
            "eth_type": "0x0800",
            "ether_type": "0x800",
            "ipv4_src": host_ip,
            "instruction_goto_table": "1"
        })
        
        # Flujo 2: tráfico con IP destino del host → goto_table:1
        flows.append({
            "switch": switch_dpid,
            "name": f"sw3_goto_table1_dst_{ip_normalized}",
            "table": "0",
            "priority": "200",
            "active": "true",
            "eth_type": "0x0800",
            "ether_type": "0x800",
            "ipv4_dst": host_ip,
            "instruction_goto_table": "1"
        })
    
    return flows


def main():
    """Función principal del script"""
    print("=" * 70)
    print("Configurador de Flujos DHCP por MAC - Controlador Floodlight")
    print("=" * 70)
    
    # Inicializar conexión al controlador
    controller_host = "127.0.0.1"
    controller_port = 8080
    
    if len(sys.argv) > 1:
        controller_host = sys.argv[1]
    if len(sys.argv) > 2:
        try:
            controller_port = int(sys.argv[2])
        except ValueError:
            print(f"Error: Puerto inválido: {sys.argv[2]}")
            sys.exit(1)
    
    controller = FloodlightController(host=controller_host, port=controller_port)
    
    # Verificar conectividad
    print(f"\n[1] Verificando conectividad con el controlador en {controller_host}:{controller_port}...")
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
                choice = input("\n¿Cuál es sw3 (hosts clientes - IP switch: 192.168.200.147)? [1-4]: ").strip()
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
                choice = input("¿Cuál es sw4 (servidor - IP switch: 192.168.200.148)? [1-4]: ").strip()
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
    
    # MAC addresses de los clientes DHCP y sus puertos en SW3
    client_config = {
        "fa:16:3e:1f:a1:d4": {"port": "4", "name": "h1", "ip": "192.168.200.4"},
        "fa:16:3e:4b:7d:ea": {"port": "5", "name": "h2", "ip": "192.168.200.2"},
        "fa:16:3e:50:27:7a": {"port": "6", "name": "h3", "ip": "192.168.200.3"}
    }
    
    # IPs de los hosts para los flujos goto_table
    host_ips = ["192.168.200.4", "192.168.200.2", "192.168.200.3"]
    
    print("\n[3] Configurando flujos DHCP para clientes:")
    for mac, config in client_config.items():
        print(f"  - {config['name']}: {mac} → SW3 puerto {config['port']}")
    
    print("\n[4] Topología de conexión:")
    print("  Hosts (SW3) → SW3 puerto 1 → SW1 puerto 3")
    print("  SW1 puerto 4 → SW4 puerto 1 → SW4 puerto 5 → Servidor DHCP")
    
    # Contadores de éxito
    total_flows = 0
    success_flows = 0
    
    # Instalar flujos para cada cliente MAC
    print("\n[5] Instalando flujos en SW3...")
    for mac, config in client_config.items():
        host_port = config["port"]
        flows_sw3 = create_sw3_flows(sw3_dpid, mac, host_port)
        for flow in flows_sw3:
            total_flows += 1
            if controller.add_flow(flow):
                print(f"  ✓ {flow['name']}")
                success_flows += 1
            else:
                print(f"  ✗ {flow['name']} - ERROR")
    
    print("\n[6] Instalando flujos en SW1...")
    for mac in client_config.keys():
        flows_sw1 = create_sw1_flows(sw1_dpid, mac)
        for flow in flows_sw1:
            total_flows += 1
            if controller.add_flow(flow):
                print(f"  ✓ {flow['name']}")
                success_flows += 1
            else:
                print(f"  ✗ {flow['name']} - ERROR")
    
    print("\n[7] Instalando flujos en SW4...")
    for mac in client_config.keys():
        flows_sw4 = create_sw4_flows(sw4_dpid, mac)
        for flow in flows_sw4:
            total_flows += 1
            if controller.add_flow(flow):
                print(f"  ✓ {flow['name']}")
                success_flows += 1
            else:
                print(f"  ✗ {flow['name']} - ERROR")
    
    # Instalar flujos goto_table para redirigir tráfico IP de/hacia hosts a tabla 1
    print("\n[8] Instalando flujos goto_table (redirigir tráfico IP de/hacia hosts a tabla 1)...")
    
    # Flujos para SW3 (incluye in_port en el flujo de origen)
    print("  Instalando flujos en SW3...")
    sw3_goto_flows = create_sw3_goto_table_flows(sw3_dpid, client_config)
    for flow in sw3_goto_flows:
        total_flows += 1
        if controller.add_flow(flow):
            print(f"    ✓ {flow['name']}")
            success_flows += 1
        else:
            print(f"    ✗ {flow['name']} - ERROR")
    
    # Flujos para SW1
    print("  Instalando flujos en SW1...")
    sw1_goto_flows = create_sw1_sw4_goto_table_flows(sw1_dpid, "sw1", host_ips)
    for flow in sw1_goto_flows:
        total_flows += 1
        if controller.add_flow(flow):
            print(f"    ✓ {flow['name']}")
            success_flows += 1
        else:
            print(f"    ✗ {flow['name']} - ERROR")
    
    # Flujos para SW4
    print("  Instalando flujos en SW4...")
    sw4_goto_flows = create_sw1_sw4_goto_table_flows(sw4_dpid, "sw4", host_ips)
    for flow in sw4_goto_flows:
        total_flows += 1
        if controller.add_flow(flow):
            print(f"    ✓ {flow['name']}")
            success_flows += 1
        else:
            print(f"    ✗ {flow['name']} - ERROR")
    
    # Verificar que los flujos estén realmente instalados en Floodlight
    print("\n[9] Verificando flujos instalados en Floodlight...")
    import time
    time.sleep(1)  # Esperar un momento para que Floodlight procese
    
    sw3_flows = controller.get_static_flows(sw3_dpid)
    sw1_flows = controller.get_static_flows(sw1_dpid)
    sw4_flows = controller.get_static_flows(sw4_dpid)
    
    sw3_count = len(sw3_flows.get(sw3_dpid, [])) if isinstance(sw3_flows.get(sw3_dpid), list) else 0
    sw1_count = len(sw1_flows.get(sw1_dpid, [])) if isinstance(sw1_flows.get(sw1_dpid), list) else 0
    sw4_count = len(sw4_flows.get(sw4_dpid, [])) if isinstance(sw4_flows.get(sw4_dpid), list) else 0
    
    # Flujos esperados: 6 DHCP (3 clientes × 2) + 6 goto_table (3 hosts × 2) = 12 por switch
    expected_flows_per_switch = len(client_config) * 2 + len(host_ips) * 2
    print(f"  SW3: {sw3_count} flujos en Floodlight (esperados: {expected_flows_per_switch})")
    print(f"  SW1: {sw1_count} flujos en Floodlight (esperados: {expected_flows_per_switch})")
    print(f"  SW4: {sw4_count} flujos en Floodlight (esperados: {expected_flows_per_switch})")
    
    # Mostrar algunos nombres de flujos para verificar y mostrar estructura de un flujo DHCP
    if sw3_flows.get(sw3_dpid):
        print(f"\n  Ejemplo de flujos en SW3 (primeros 3):")
        for i, flow_item in enumerate(sw3_flows.get(sw3_dpid)[:3]):
            if isinstance(flow_item, dict):
                for flow_name, flow_data in flow_item.items():
                    print(f"    - {flow_name}")
                    if 'dhcp' in flow_name.lower() and isinstance(flow_data, dict):
                        # Mostrar estructura completa del flujo DHCP para debugging
                        print(f"      Estructura completa:")
                        print(f"        table={flow_data.get('table', 'N/A')}")
                        print(f"        priority={flow_data.get('priority', 'N/A')}")
                        match = flow_data.get('match', {})
                        if match:
                            print(f"        Match: {json.dumps(match, indent=10)}")
                        instructions = flow_data.get('instructions', {})
                        if instructions:
                            print(f"        Instructions: {json.dumps(instructions, indent=10)}")
                        elif 'actions' in flow_data:
                            print(f"        Actions: {flow_data.get('actions', 'N/A')}")
                        # Comparar con flujo de tabla miss que SÍ funciona
                        if i == 0:  # Solo para el primer flujo DHCP
                            print(f"\n      Comparando con flujo tabla miss (que SÍ funciona):")
                            table_miss_flows = [f for f in sw3_flows.get(sw3_dpid) if isinstance(f, dict) and 'table_miss' in str(f)]
                            if table_miss_flows:
                                for tm_flow in table_miss_flows:
                                    for tm_name, tm_data in tm_flow.items():
                                        if 'table_miss' in tm_name:
                                            print(f"        Tabla miss - table={tm_data.get('table', 'N/A')}, priority={tm_data.get('priority', 'N/A')}")
                                            tm_match = tm_data.get('match', {})
                                            print(f"        Tabla miss - match: {json.dumps(tm_match, indent=10)}")
                                            tm_instructions = tm_data.get('instructions', {})
                                            if tm_instructions:
                                                print(f"        Tabla miss - instructions: {json.dumps(tm_instructions, indent=10)}")
                                            break
                        break
    
    # Resumen
    print("\n" + "=" * 70)
    print("RESUMEN")
    print("=" * 70)
    print(f"Total de flujos instalados: {success_flows}/{total_flows}")
    print(f"Flujos en Floodlight: SW3={sw3_count}, SW1={sw1_count}, SW4={sw4_count}")
    print(f"Clientes DHCP configurados: {len(client_config)}")
    print(f"Switches configurados: SW3, SW1, SW4")
    print(f"Servidor DHCP: conectado a SW4 puerto 5")
    print("\nClientes configurados:")
    for mac, config in client_config.items():
        print(f"  - {config['name']}: {mac} en SW3 puerto {config['port']}")
    
    if success_flows == total_flows and sw3_count >= expected_flows_per_switch:
        print("\n✓ Todos los flujos se instalaron correctamente!")
        return 0
    else:
        print(f"\n⚠ {total_flows - success_flows} flujos no se pudieron instalar. Revisa los errores arriba.")
        if sw3_count < expected_flows_per_switch:
            print(f"⚠ ADVERTENCIA: Solo {sw3_count} flujos están en Floodlight para SW3, se esperaban {expected_flows_per_switch}")
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

