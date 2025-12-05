#!/usr/bin/env python3
"""
Script para listar los switches y hosts conectados al controlador Floodlight

NOTA: Los switches no siempre muestran nombre porque la API de Floodlight
      no proporciona esta información en todas las versiones. El DPID (Data Path
      Identifier) es el identificador único de cada switch.

Uso:
    python listar_switches.py                    # Lista switches y hosts (localhost:8080)
    python listar_switches.py 192.168.1.100      # Especificar host
    python listar_switches.py 192.168.1.100 8080 # Especificar host y puerto
    python listar_switches.py --debug            # Mostrar respuesta JSON completa

Autor: Script generado para configuración de red SDN
Fecha: 2024
"""

import requests
import sys
import json
from typing import List, Dict


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
        except requests.exceptions.RequestException as e:
            print(f"Error al obtener switches: {e}")
            return []
    
    def get_hosts(self) -> List[Dict]:
        """
        Obtiene la lista de hosts/dispositivos conectados a la red
        
        Returns:
            Lista de diccionarios con información de los hosts
        """
        try:
            url = f"{self.base_url}/wm/device/"
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            data = response.json()
            # La respuesta puede venir como un diccionario con una clave 'devices'
            if isinstance(data, dict) and 'devices' in data:
                return data['devices']
            elif isinstance(data, list):
                return data
            else:
                return []
        except requests.exceptions.RequestException as e:
            print(f"Error al obtener hosts: {e}")
            return []


def list_switches(host: str = "127.0.0.1", port: int = 8080, debug: bool = False):
    """
    Lista todos los switches y hosts conectados al controlador
    
    Args:
        host: Dirección IP del controlador
        port: Puerto del controlador
        debug: Si es True, muestra la respuesta JSON completa
    """
    print("=" * 70)
    print("LISTADO DE SWITCHES Y HOSTS - CONTROLADOR FLOODLIGHT")
    print("=" * 70)
    
    # Inicializar conexión al controlador
    controller = FloodlightController(host=host, port=port)
    
    # Obtener switches
    print(f"\nConectando al controlador en {host}:{port}...")
    switches = controller.get_switches()
    
    if not switches:
        print("\n❌ ERROR: No se pudo conectar al controlador o no hay switches conectados.")
        print("\nAsegúrate de que:")
        print("  - El túnel SSH esté activo (si aplica):")
        print("    ssh -L 8080:192.168.201.200:8080 ubuntu@10.20.12.110")
        print("  - El controlador Floodlight esté ejecutándose")
        print("  - Los switches estén conectados al controlador")
        return 1
    
    # Modo debug: mostrar JSON completo
    if debug:
        print("\n" + "=" * 70)
        print("RESPUESTA JSON COMPLETA (DEBUG)")
        print("=" * 70)
        print(json.dumps(switches, indent=2))
        print("=" * 70 + "\n")
    
    # Mostrar información de los switches
    print(f"\n✓ Controlador conectado exitosamente")
    print(f"✓ Switches encontrados: {len(switches)}")
    print("\n" + "-" * 70)
    
    for i, switch in enumerate(switches, 1):
        dpid = switch.get('switchDPID', switch.get('dpid', 'N/A'))
        
        # Intentar obtener nombre de diferentes campos posibles
        name = (switch.get('switchName') or 
                switch.get('name') or 
                switch.get('switchName') or
                'N/A')
        
        # Información de descripción del switch
        desc = switch.get('switchDescription', {})
        if isinstance(desc, dict):
            hardware = desc.get('hardware', desc.get('manufacturer', 'N/A'))
            software = desc.get('software', desc.get('datapathDescription', 'N/A'))
        else:
            hardware = 'N/A'
            software = 'N/A'
        
        # Intentar obtener información adicional
        inet_address = switch.get('inetAddress', 'N/A')
        connected_since = switch.get('connectedSince', 'N/A')
        
        print(f"\n[{i}] Switch #{i}")
        if name != 'N/A':
            print(f"    Nombre:        {name}")
        print(f"    DPID:          {dpid}")
        
        # Mostrar dirección IP si está disponible
        if inet_address != 'N/A':
            print(f"    Dirección IP:  {inet_address}")
        
        # Mostrar información de hardware/software si está disponible
        if hardware != 'N/A':
            print(f"    Hardware:      {hardware}")
        if software != 'N/A':
            print(f"    Software:      {software}")
        
        # Mostrar puertos con detalles
        if 'ports' in switch:
            ports = switch['ports']
            if ports:
                print(f"    Puertos:       {len(ports)} puertos disponibles")
                # Mostrar algunos puertos activos si existen
                active_ports = [p for p in ports if p.get('state', {}).get('linkDown', True) == False]
                if active_ports:
                    print(f"    Puertos activos: {len(active_ports)}")
        
        # Mostrar fecha de conexión si está disponible
        if connected_since != 'N/A':
            print(f"    Conectado desde: {connected_since}")
        
        print("-" * 70)
    
    print(f"\n✓ Total de switches: {len(switches)}")
    print("\n💡 NOTA: Los switches no muestran nombre porque la API de Floodlight")
    print("         no siempre proporciona esta información. El DPID es el")
    print("         identificador único de cada switch.")
    
    # Obtener y mostrar hosts
    print("\n" + "=" * 70)
    print("LISTADO DE HOSTS/DISPOSITIVOS CONECTADOS")
    print("=" * 70)
    
    hosts = controller.get_hosts()
    
    if not hosts:
        print("\n⚠ No se encontraron hosts conectados.")
        print("   Los hosts aparecerán cuando se conecten a la red y")
        print("   el controlador los detecte.")
    else:
        print(f"\n✓ Hosts encontrados: {len(hosts)}")
        print("\n" + "-" * 70)
        
        # Modo debug: mostrar JSON completo de hosts
        if debug:
            print("\n" + "=" * 70)
            print("RESPUESTA JSON COMPLETA DE HOSTS (DEBUG)")
            print("=" * 70)
            print(json.dumps(hosts, indent=2))
            print("=" * 70 + "\n")
        
        for i, host in enumerate(hosts, 1):
            # Obtener MAC address
            mac = host.get('mac', host.get('macAddress', ['N/A']))
            if isinstance(mac, list) and len(mac) > 0:
                mac = mac[0]
            elif not mac or mac == []:
                mac = 'N/A'
            
            # Obtener direcciones IP
            ipv4 = host.get('ipv4', [])
            if isinstance(ipv4, list) and len(ipv4) > 0:
                ipv4 = ipv4[0] if ipv4 else 'N/A'
            else:
                ipv4 = 'N/A'
            
            # Obtener switch y puerto de conexión
            attachment_point = host.get('attachmentPoint', [])
            switch_dpid = 'N/A'
            port = 'N/A'
            
            if isinstance(attachment_point, list) and len(attachment_point) > 0:
                ap = attachment_point[0]
                if isinstance(ap, dict):
                    switch_dpid = ap.get('switchDPID', ap.get('switch', 'N/A'))
                    port = ap.get('port', 'N/A')
            elif isinstance(attachment_point, dict):
                switch_dpid = attachment_point.get('switchDPID', attachment_point.get('switch', 'N/A'))
                port = attachment_point.get('port', 'N/A')
            
            # Obtener VLAN si está disponible
            vlan = host.get('vlan', host.get('vlanId', 'N/A'))
            
            print(f"\n[{i}] Host #{i}")
            print(f"    MAC Address:   {mac}")
            if ipv4 != 'N/A':
                print(f"    Dirección IP:  {ipv4}")
            if switch_dpid != 'N/A':
                print(f"    Switch (DPID): {switch_dpid}")
            if port != 'N/A':
                print(f"    Puerto:        {port}")
            if vlan != 'N/A' and vlan != []:
                vlan_str = vlan[0] if isinstance(vlan, list) else str(vlan)
                print(f"    VLAN:          {vlan_str}")
            
            print("-" * 70)
        
        print(f"\n✓ Total de hosts: {len(hosts)}")
    
    if not debug:
        print("\n💡 Para ver toda la información disponible, ejecuta con --debug")
    
    print("=" * 70)
    
    return 0


def main():
    """Función principal del script"""
    # Puedes cambiar estos valores si el controlador está en otra ubicación
    controller_host = "127.0.0.1"
    controller_port = 8080
    debug_mode = False
    
    # Procesar argumentos de línea de comandos
    args = sys.argv[1:]
    
    # Verificar si hay --debug
    if '--debug' in args:
        debug_mode = True
        args.remove('--debug')
    
    # Si se proporcionan argumentos, usarlos como host y puerto
    if len(args) >= 1:
        controller_host = args[0]
    if len(args) >= 2:
        try:
            controller_port = int(args[1])
        except ValueError:
            print(f"ERROR: El puerto debe ser un número válido")
            sys.exit(1)
    
    try:
        sys.exit(list_switches(controller_host, controller_port, debug_mode))
    except KeyboardInterrupt:
        print("\n\nOperación cancelada por el usuario.")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR INESPERADO: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

