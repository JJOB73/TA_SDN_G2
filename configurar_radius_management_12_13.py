#!/usr/bin/env python3
"""
Script para configurar flujos OpenFlow en SW2 y SW4 para permitir comunicación
entre el servidor RADIUS/LDAP y el servidor de management.

Servidores:
  - RADIUS/LDAP: 192.168.200.12 conectado a SW2 por el puerto 5
  - Management: 192.168.200.13 conectado a SW4 por el puerto 5

Protocolos permitidos:
  - ARP (resolución de direcciones MAC) - NOTA: Debe agregarse manualmente con ovs-ofctl
  - UDP (todos los puertos UDP)
  - ICMP (ping y otros)

NOTA IMPORTANTE SOBRE ARP:
  Floodlight no soporta la acción NORMAL a través de su API REST. Para agregar
  el flujo ARP con actions=NORMAL, ejecuta manualmente en cada switch:
  
  sudo ovs-ofctl -O OpenFlow13 add-flow sw2 "priority=500,arp,actions=NORMAL"
  sudo ovs-ofctl -O OpenFlow13 add-flow sw4 "priority=500,arp,actions=NORMAL"

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
            ip_address: Dirección IP del switch (ej: "192.168.200.146")
            
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


def create_sw2_flows(switch_dpid: str) -> List[Dict]:
    """
    Crea la lista de flujos para SW2 (servidor RADIUS/LDAP: 192.168.200.12)
    
    Args:
        switch_dpid: DPID del switch SW2
        
    Returns:
        Lista de diccionarios con las definiciones de flujos
    """
    flows = [
        # UDP: todo tráfico UDP desde puerto 5 hacia puerto 3
        {
            "switch": switch_dpid,
            "name": "sw2_udp_5_to_3",
            "table": "0",
            "priority": "200",
            "in_port": "5",
            "eth_type": "0x0800",
            "ip_proto": "17",
            "actions": "output=3"
        },
        # UDP: todo tráfico UDP desde puerto 3 hacia puerto 5
        {
            "switch": switch_dpid,
            "name": "sw2_udp_3_to_5",
            "table": "0",
            "priority": "200",
            "in_port": "3",
            "eth_type": "0x0800",
            "ip_proto": "17",
            "actions": "output=5"
        },
        # ICMP: desde RADIUS (192.168.200.12) hacia Management (192.168.200.13)
        {
            "switch": switch_dpid,
            "name": "sw2_icmp_5_to_3",
            "table": "0",
            "priority": "300",
            "in_port": "5",
            "eth_type": "0x0800",
            "ip_proto": "1",
            "ipv4_src": "192.168.200.12",
            "ipv4_dst": "192.168.200.13",
            "actions": "output=3"
        },
        # ICMP: desde Management (192.168.200.13) hacia RADIUS (192.168.200.12)
        {
            "switch": switch_dpid,
            "name": "sw2_icmp_3_to_5",
            "table": "0",
            "priority": "300",
            "in_port": "3",
            "eth_type": "0x0800",
            "ip_proto": "1",
            "ipv4_src": "192.168.200.13",
            "ipv4_dst": "192.168.200.12",
            "actions": "output=5"
        }
    ]
    return flows


def create_sw4_flows(switch_dpid: str) -> List[Dict]:
    """
    Crea la lista de flujos para SW4 (servidor de management: 192.168.200.13)
    
    Args:
        switch_dpid: DPID del switch SW4
        
    Returns:
        Lista de diccionarios con las definiciones de flujos
    """
    flows = [
        # UDP: todo tráfico UDP desde puerto 5 hacia puerto 2
        {
            "switch": switch_dpid,
            "name": "sw4_udp_5_to_2",
            "table": "0",
            "priority": "200",
            "in_port": "5",
            "eth_type": "0x0800",
            "ip_proto": "17",
            "actions": "output=2"
        },
        # UDP: todo tráfico UDP desde puerto 2 hacia puerto 5
        {
            "switch": switch_dpid,
            "name": "sw4_udp_2_to_5",
            "table": "0",
            "priority": "200",
            "in_port": "2",
            "eth_type": "0x0800",
            "ip_proto": "17",
            "actions": "output=5"
        },
        # ICMP: desde Management (192.168.200.13) hacia RADIUS (192.168.200.12)
        {
            "switch": switch_dpid,
            "name": "sw4_icmp_5_to_2",
            "table": "0",
            "priority": "300",
            "in_port": "5",
            "eth_type": "0x0800",
            "ip_proto": "1",
            "ipv4_src": "192.168.200.13",
            "ipv4_dst": "192.168.200.12",
            "actions": "output=2"
        },
        # ICMP: desde RADIUS (192.168.200.12) hacia Management (192.168.200.13)
        {
            "switch": switch_dpid,
            "name": "sw4_icmp_2_to_5",
            "table": "0",
            "priority": "300",
            "in_port": "2",
            "eth_type": "0x0800",
            "ip_proto": "1",
            "ipv4_src": "192.168.200.12",
            "ipv4_dst": "192.168.200.13",
            "actions": "output=5"
        }
    ]
    return flows


def main():
    """Función principal del script"""
    print("=" * 60)
    print("Configurador de Flujos OpenFlow 1.3 para RADIUS/Management")
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
    
    # Obtener DPIDs de SW2 y SW4 por IP
    print("\n[2] Obteniendo identificadores de switches por IP...")
    
    # Mapeo de IPs de los switches (no de los servidores)
    switch_ips = {
        "sw2": "192.168.200.146",
        "sw4": "192.168.200.148"
    }
    
    sw2_dpid = controller.get_switch_dpid_by_ip(switch_ips["sw2"])
    sw4_dpid = controller.get_switch_dpid_by_ip(switch_ips["sw4"])
    
    # Si no se encontraron por IP, permitir selección manual
    if not sw2_dpid or not sw4_dpid:
        print("\n⚠ No se pudieron identificar automáticamente los switches por IP.")
        print("Switches disponibles:")
        for i, switch in enumerate(switches, 1):
            dpid = switch.get('switchDPID', 'N/A')
            name = switch.get('switchName', 'N/A')
            inet = switch.get('inetAddress', 'N/A')
            print(f"  [{i}] {name} - IP: {inet} - DPID: {dpid}")
        
        if not sw2_dpid:
            try:
                choice = input("\n¿Cuál es sw2 (RADIUS/LDAP - IP switch: 192.168.200.146)? [1-4]: ").strip()
                idx = int(choice) - 1
                if 0 <= idx < len(switches):
                    sw2_dpid = switches[idx].get('switchDPID')
                    print(f"✓ sw2 seleccionado: {sw2_dpid}")
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
        print(f"✓ sw2 encontrado por IP {switch_ips['sw2']}: {sw2_dpid}")
        print(f"✓ sw4 encontrado por IP {switch_ips['sw4']}: {sw4_dpid}")
    
    # Crear definiciones de flujos
    print("\n[3] Creando definiciones de flujos...")
    print("  Servidor RADIUS/LDAP: 192.168.200.12 (SW2 puerto 5)")
    print("  Servidor Management: 192.168.200.13 (SW4 puerto 5)")
    flows_sw2 = create_sw2_flows(sw2_dpid)
    flows_sw4 = create_sw4_flows(sw4_dpid)
    print(f"✓ {len(flows_sw2)} flujos para sw2")
    print(f"✓ {len(flows_sw4)} flujos para sw4")
    
    # Eliminar flujos existentes (opcional pero recomendado)
    print("\n[3.5] Eliminando flujos existentes...")
    print("  Eliminando flujos de sw2...")
    controller.delete_all_flows(sw2_dpid)
    print("  Eliminando flujos de sw4...")
    controller.delete_all_flows(sw4_dpid)
    print("  ✓ Flujos antiguos eliminados")
    time.sleep(1)  # Esperar un momento para que se procesen las eliminaciones
    
    # Instalar flujos en SW2
    print("\n[4] Instalando flujos en sw2...")
    success_sw2 = 0
    for flow in flows_sw2:
        if controller.add_flow(flow):
            print(f"  ✓ {flow['name']}")
            success_sw2 += 1
        else:
            print(f"  ✗ {flow['name']} - ERROR")
    
    # Instalar flujos en SW4
    print("\n[5] Instalando flujos en sw4...")
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
    print(f"sw2: {success_sw2}/{len(flows_sw2)} flujos instalados")
    print(f"sw4: {success_sw4}/{len(flows_sw4)} flujos instalados")
    
    if success_sw2 == len(flows_sw2) and success_sw4 == len(flows_sw4):
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

