#!/usr/bin/env python3
"""
Dashboard web para monitorear la red SDN usando Flask
Muestra información de switches, hosts y flujos en tiempo real
"""

from flask import Flask, render_template, jsonify, request
import requests
import json
from typing import Dict, List, Optional
from datetime import datetime
import threading
import time
import subprocess
import os
import sys

app = Flask(__name__)

# Configuración del controlador Floodlight
FLOODLIGHT_HOST = "127.0.0.1"
FLOODLIGHT_PORT = 8080


class FloodlightController:
    """Clase para interactuar con la API REST de Floodlight"""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.base_url = f"http://{host}:{port}"
        self.headers = {'Content-Type': 'application/json'}
    
    def get_switches(self) -> List[Dict]:
        """Obtiene la lista de switches conectados al controlador"""
        try:
            url = f"{self.base_url}/wm/core/controller/switches/json"
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException:
            return []
    
    def get_hosts(self) -> List[Dict]:
        """Obtiene la lista de hosts/dispositivos conectados a la red"""
        try:
            url = f"{self.base_url}/wm/device/"
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            data = response.json()
            if isinstance(data, dict) and 'devices' in data:
                return data['devices']
            elif isinstance(data, list):
                return data
            else:
                return []
        except requests.exceptions.RequestException:
            return []
    
    def get_flows(self, switch_dpid: str) -> List[Dict]:
        """Obtiene los flujos de un switch específico usando el endpoint de estadísticas"""
        flows_list = []
        
        # Intentar múltiples endpoints de Floodlight para obtener todos los flujos
        endpoints_to_try = [
            f"{self.base_url}/wm/core/switch/{switch_dpid}/flow/json",
            f"{self.base_url}/wm/core/switch/{switch_dpid}/flow/desc/0/json",
            f"{self.base_url}/wm/core/switch/{switch_dpid}/flow/stats/json"
        ]
        
        for url in endpoints_to_try:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    flow_data = response.json()
                    
                    # El formato puede variar, intentar diferentes estructuras
                    flows = []
                    if isinstance(flow_data, dict):
                        # Buscar diferentes claves posibles
                        flows = (flow_data.get('flows') or 
                                flow_data.get('flow') or 
                                flow_data.get('flowStats') or 
                                flow_data.get('flow-stats') or [])
                        if not isinstance(flows, list):
                            flows = [flows] if flows else []
                    elif isinstance(flow_data, list):
                        flows = flow_data
                    
                    # Procesar cada flujo
                    for flow_entry in flows:
                        if not isinstance(flow_entry, dict):
                            continue
                        
                        # Extraer match fields
                        match = flow_entry.get('match', {})
                        if not match:
                            # Construir match desde campos individuales si están disponibles
                            match = {}
                            for key in ['in_port', 'eth_type', 'ip_proto', 'udp_src', 'udp_dst', 
                                       'tcp_src', 'tcp_dst', 'ipv4_src', 'ipv4_dst', 
                                       'dl_src', 'dl_dst', 'eth_src', 'eth_dst', 'tp_src', 'tp_dst']:
                                if key in flow_entry:
                                    match[key] = flow_entry[key]
                        
                        # Extraer actions - buscar en múltiples ubicaciones
                        actions = []
                        
                        # 1. Buscar directamente en 'actions'
                        direct_actions = flow_entry.get('actions')
                        
                        # Procesar actions directo
                        if direct_actions:
                            if isinstance(direct_actions, str):
                                actions.append(direct_actions)
                            elif isinstance(direct_actions, list):
                                for action in direct_actions:
                                    if isinstance(action, str):
                                        actions.append(action)
                                    elif isinstance(action, dict):
                                        if 'output' in action:
                                            actions.append(f"output:{action['output']}")
                                        elif 'drop' in action:
                                            actions.append("drop")
                                        elif 'controller' in action:
                                            actions.append(f"CONTROLLER:{action.get('controller', '')}")
                        
                        # 2. Buscar en 'instructions'
                        instructions = flow_entry.get('instructions', {})
                        if not actions and isinstance(instructions, dict):
                            # Buscar instruction_goto_table primero
                            goto_table = instructions.get('instruction_goto_table')
                            if goto_table:
                                # Puede ser un string directo "1" o un objeto {"instruction_goto_table": "1"}
                                if isinstance(goto_table, str):
                                    table_id = goto_table
                                elif isinstance(goto_table, dict):
                                    # Buscar el table_id en diferentes ubicaciones posibles
                                    table_id = (goto_table.get('table_id') or 
                                               goto_table.get('instruction_goto_table') or
                                               goto_table.get('tableId') or
                                               '1')
                                else:
                                    table_id = str(goto_table)
                                actions.append(f"goto_table:{table_id}")
                            
                            # Si no hay goto_table, buscar instruction_apply_actions
                            if not actions:
                                apply_actions = instructions.get('instruction_apply_actions', {})
                                
                                if isinstance(apply_actions, dict):
                                    action_data = apply_actions.get('actions')
                                    
                                    # Si actions es un string (como "output=1"), usarlo directamente
                                    if isinstance(action_data, str):
                                        actions.append(action_data)
                                    # Si actions es una lista, procesarla
                                    elif isinstance(action_data, list):
                                        for action in action_data:
                                            if isinstance(action, str):
                                                actions.append(action)
                                            elif isinstance(action, dict):
                                                if 'output' in action:
                                                    output_port = action.get('output', '')
                                                    actions.append(f"output:{output_port}")
                                                elif 'drop' in action:
                                                    actions.append("drop")
                                                elif 'controller' in action:
                                                    controller_port = action.get('controller', '')
                                                    actions.append(f"CONTROLLER:{controller_port}")
                                    # Si actions es un dict, puede estar en formato diferente
                                    elif isinstance(action_data, dict):
                                        if 'output' in action_data:
                                            actions.append(f"output:{action_data['output']}")
                                        elif 'drop' in action_data:
                                            actions.append("drop")
                                        elif 'controller' in action_data:
                                            actions.append(f"CONTROLLER:{action_data['controller']}")
                                    # Verificar si hay "none": "drop"
                                    elif 'none' in apply_actions and apply_actions.get('none') == 'drop':
                                        actions.append("drop")
                        
                        # 3. Buscar en 'instruction' (singular)
                        instruction = flow_entry.get('instruction', {})
                        if not actions and isinstance(instruction, dict):
                            apply_actions = instruction.get('instruction_apply_actions', {})
                            if isinstance(apply_actions, dict):
                                action_data = apply_actions.get('actions')
                                if isinstance(action_data, str):
                                    actions.append(action_data)
                                elif isinstance(action_data, list):
                                    for action in action_data:
                                        if isinstance(action, dict):
                                            if 'output' in action:
                                                actions.append(f"output:{action.get('output', '')}")
                                            elif 'drop' in action:
                                                actions.append("drop")
                        
                        # Construir el objeto de flujo
                        flow_obj = {
                            'name': flow_entry.get('name', f"flow_{flow_entry.get('id', 'unknown')}"),
                            'priority': str(flow_entry.get('priority', '0')),
                            'table': str(flow_entry.get('table_id', flow_entry.get('table', '0'))),
                            'match': match,
                            'actions': ', '.join(actions) if actions else 'N/A',
                            'cookie': str(flow_entry.get('cookie', '0')),
                            'packet_count': flow_entry.get('packet_count', flow_entry.get('packetCount', 0)),
                            'byte_count': flow_entry.get('byte_count', flow_entry.get('byteCount', 0)),
                            'duration': flow_entry.get('duration_sec', flow_entry.get('duration', 0))
                        }
                        
                        flows_list.append(flow_obj)
                    
                    # Si encontramos flujos, retornarlos
                    if flows_list:
                        return flows_list
                        
            except requests.exceptions.RequestException:
                continue
        
        # Si ningún endpoint funcionó, intentar con el endpoint de flujos estáticos como fallback
        try:
            url = f"{self.base_url}/wm/staticflowpusher/list/{switch_dpid}/json"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                static_flows = response.json()
                if isinstance(static_flows, list):
                    return static_flows
                elif isinstance(static_flows, dict):
                    return [static_flows]
        except:
            pass
        
        return flows_list
    
    def get_all_flows(self) -> Dict[str, List[Dict]]:
        """Obtiene todos los flujos de todos los switches"""
        switches = self.get_switches()
        all_flows = {}
        for switch in switches:
            dpid = switch.get('switchDPID', '')
            if dpid:
                flows = self.get_flows(dpid)
                all_flows[dpid] = flows
        return all_flows
    
    def clear_static_flows(self, switch_dpid: str) -> bool:
        """
        Elimina todos los flujos estáticos (creados por API REST) de un switch
        
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


# Instancia global del controlador
controller = FloodlightController(FLOODLIGHT_HOST, FLOODLIGHT_PORT)

# Mapeo de DPIDs a nombres de switches
SWITCH_NAMES = {
    "00:00:72:e0:80:7e:85:4c": "SW2",
    "00:00:5e:c7:6e:c6:11:4c": "SW1",
    "00:00:ea:3f:f0:79:32:43": "SW4",
    "00:00:f2:20:f9:45:4c:4e": "SW3"
}

# Mapeo de IPs a nombres de switches (fallback)
SWITCH_IPS = {
    "192.168.200.145": "SW1",
    "192.168.200.146": "SW2",
    "192.168.200.147": "SW3",
    "192.168.200.148": "SW4"
}


def extract_ip_addresses(host: Dict) -> List[str]:
    """Extrae todas las direcciones IP de un host"""
    ips = []
    ipv4 = host.get('ipv4', [])
    if isinstance(ipv4, list):
        ips.extend([ip for ip in ipv4 if isinstance(ip, str) and ip])
    elif isinstance(ipv4, str) and ipv4:
        ips.append(ipv4)
    
    ip_address = host.get('ipAddress', [])
    if isinstance(ip_address, list):
        ips.extend([ip for ip in ip_address if isinstance(ip, str) and ip])
    elif isinstance(ip_address, str) and ip_address:
        ips.append(ip_address)
    
    return list(set(ips))


@app.route('/')
def index():
    """Página principal del dashboard"""
    return render_template('dashboard.html')


def get_switch_name(dpid: str, inet_address: str = '') -> str:
    """
    Obtiene el nombre del switch basado en su DPID o IP
    
    Args:
        dpid: DPID del switch
        inet_address: Dirección IP del switch (opcional, para fallback)
        
    Returns:
        Nombre del switch (SW1, SW2, SW3, SW4) o nombre genérico
    """
    # Primero intentar por DPID
    if dpid and dpid in SWITCH_NAMES:
        return SWITCH_NAMES[dpid]
    
    # Si no se encuentra por DPID, intentar por IP
    if inet_address and inet_address != 'N/A':
        # Extraer IP de la dirección (puede venir como "/IP:PORT")
        ip = inet_address.split(':')[0].replace('/', '')
        if ip in SWITCH_IPS:
            return SWITCH_IPS[ip]
    
    # Si no se encuentra, usar nombre genérico
    return f"Switch {dpid[-4:]}" if dpid and len(dpid) >= 4 else "Switch Desconocido"


@app.route('/api/switches')
def api_switches():
    """API endpoint para obtener switches"""
    switches = controller.get_switches()
    switches_data = []
    
    for switch in switches:
        dpid = switch.get('switchDPID', 'N/A')
        inet_address = switch.get('inetAddress', 'N/A')
        
        # Obtener nombre del switch usando la lógica de identificación
        switch_name = get_switch_name(dpid, inet_address)
        
        # Obtener información de puertos
        ports = switch.get('ports', [])
        active_ports = [p for p in ports if not p.get('state', {}).get('linkDown', True)] if ports else []
        
        switches_data.append({
            'dpid': dpid,
            'name': switch_name,
            'ip': inet_address if inet_address != 'N/A' else 'Unknown',
            'total_ports': len(ports) if ports else 0,
            'active_ports': len(active_ports),
            'connected_since': switch.get('connectedSince', 'Unknown')
        })
    
    return jsonify({
        'success': True,
        'switches': switches_data,
        'count': len(switches_data),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/hosts')
def api_hosts():
    """API endpoint para obtener hosts"""
    hosts = controller.get_hosts()
    hosts_data = []
    
    for host in hosts:
        # Obtener MAC address
        mac = host.get('mac', host.get('macAddress', []))
        if isinstance(mac, list) and len(mac) > 0:
            mac = mac[0]
        elif not mac or mac == []:
            mac = 'N/A'
        
        # Extraer IPs
        ip_addresses = extract_ip_addresses(host)
        
        # Obtener switch y puerto de conexión
        attachment_point = host.get('attachmentPoint', [])
        switch_dpid = 'N/A'
        port = 'N/A'
        
        if isinstance(attachment_point, list) and len(attachment_point) > 0:
            ap = attachment_point[0]
            if isinstance(ap, dict):
                switch_dpid = ap.get('switchDPID', ap.get('switch', 'N/A'))
                port_raw = ap.get('port', 'N/A')
                # Convertir puerto a string explícitamente
                if port_raw != 'N/A' and port_raw is not None:
                    port = str(port_raw)
                else:
                    port = 'N/A'
        elif isinstance(attachment_point, dict):
            switch_dpid = attachment_point.get('switchDPID', attachment_point.get('switch', 'N/A'))
            port_raw = attachment_point.get('port', 'N/A')
            # Convertir puerto a string explícitamente
            if port_raw != 'N/A' and port_raw is not None:
                port = str(port_raw)
            else:
                port = 'N/A'
        
        # Obtener nombre del switch usando la función de identificación
        switch_name = get_switch_name(switch_dpid) if switch_dpid != 'N/A' else 'Desconocido'
        
        # Verificar si está conectado a SW3
        is_sw3 = (switch_dpid == "00:00:f2:20:f9:45:4c:4e" or switch_name == "SW3")
        has_ip = len(ip_addresses) > 0
        
        hosts_data.append({
            'mac': mac,
            'ips': ip_addresses,
            'switch_dpid': switch_dpid,
            'switch_name': switch_name,
            'port': port,
            'vlan': host.get('vlan', host.get('vlanId', 'N/A')),
            'is_sw3': is_sw3,
            'has_ip': has_ip
        })
    
    return jsonify({
        'success': True,
        'hosts': hosts_data,
        'count': len(hosts_data),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/flows')
def api_flows():
    """API endpoint para obtener todos los flujos"""
    all_flows = controller.get_all_flows()
    
    flows_data = {}
    total_flows = 0
    
    for dpid, flows in all_flows.items():
        flows_list = []
        if isinstance(flows, list):
            for flow in flows:
                flows_list.append({
                    'name': flow.get('name', 'Unknown'),
                    'priority': flow.get('priority', 'N/A'),
                    'match': flow.get('match', {}),
                    'actions': flow.get('actions', 'N/A')
                })
        flows_data[dpid] = flows_list
        total_flows += len(flows_list)
    
    return jsonify({
        'success': True,
        'flows': flows_data,
        'total_flows': total_flows,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/flows/<switch_dpid>')
def api_switch_flows(switch_dpid):
    """API endpoint para obtener flujos de un switch específico"""
    try:
        flows = controller.get_flows(switch_dpid)
        flows_list = []
        
        if isinstance(flows, list):
            for flow in flows:
                # Extraer información del flujo
                # El formato puede variar dependiendo de si viene de staticflowpusher o de flow stats
                match_fields = flow.get('match', {})
                
                # Intentar obtener actions de diferentes formatos
                actions = flow.get('actions', 'N/A')
                if actions == 'N/A' and 'instructions' in flow:
                    # Formato de flow stats
                    instructions = flow.get('instructions', {})
                    if isinstance(instructions, dict):
                        instruction_list = instructions.get('instruction_apply_actions', {}).get('actions', [])
                        action_list = []
                        for action in instruction_list:
                            if 'output' in action:
                                action_list.append(f"output:{action['output']}")
                            elif 'drop' in action:
                                action_list.append("drop")
                            elif 'controller' in action:
                                action_list.append("CONTROLLER")
                        actions = ', '.join(action_list) if action_list else 'N/A'
                
                # Si match_fields está vacío, intentar construir desde otros campos
                if not match_fields or match_fields == {}:
                    match_fields = {}
                    # Buscar campos comunes de match en el flujo
                    for key in ['in_port', 'eth_type', 'ip_proto', 'udp_src', 'udp_dst', 
                               'tcp_src', 'tcp_dst', 'ipv4_src', 'ipv4_dst', 
                               'dl_src', 'dl_dst', 'eth_src', 'eth_dst', 'tp_src', 'tp_dst']:
                        if key in flow:
                            match_fields[key] = flow[key]
                
                flow_data = {
                    'name': flow.get('name', f"flow_{flow.get('id', 'unknown')}"),
                    'priority': str(flow.get('priority', 'N/A')),
                    'table': str(flow.get('table', flow.get('table_id', 'N/A'))),
                    'match': match_fields,
                    'actions': actions,
                    'cookie': str(flow.get('cookie', '0')),
                    'active': flow.get('active', 'true')
                }
                
                # Agregar estadísticas si están disponibles
                if 'packet_count' in flow:
                    flow_data['packet_count'] = flow.get('packet_count', 0)
                    flow_data['byte_count'] = flow.get('byte_count', 0)
                    flow_data['duration'] = flow.get('duration', flow.get('duration_sec', 0))
                
                flows_list.append(flow_data)
        elif isinstance(flows, dict):
            # Si es un solo flujo en formato dict
            match_fields = flows.get('match', {})
            actions = flows.get('actions', 'N/A')
            flows_list.append({
                'name': flows.get('name', 'Unknown'),
                'priority': str(flows.get('priority', 'N/A')),
                'table': str(flows.get('table', 'N/A')),
                'match': match_fields,
                'actions': actions,
                'cookie': str(flows.get('cookie', 'N/A')),
                'active': flows.get('active', 'N/A')
            })
        
        # Obtener nombre del switch
        switch_name = get_switch_name(switch_dpid)
        
        return jsonify({
            'success': True,
            'switch_dpid': switch_dpid,
            'switch_name': switch_name,
            'flows': flows_list,
            'count': len(flows_list),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc(),
            'timestamp': datetime.now().isoformat()
        }), 500


@app.route('/api/status')
def api_status():
    """API endpoint para verificar el estado del controlador"""
    try:
        switches = controller.get_switches()
        hosts = controller.get_hosts()
        
        return jsonify({
            'success': True,
            'controller_connected': True,
            'switches_count': len(switches),
            'hosts_count': len(hosts),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'controller_connected': False,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500


@app.route('/api/create_host_flows', methods=['POST'])
def api_create_host_flows():
    """API endpoint para crear flujos de portal cautivo para un host"""
    try:
        if not request.json:
            return jsonify({
                'success': False,
                'error': 'No se recibieron datos JSON'
            }), 400
            
        data = request.json
        host_ip = data.get('host_ip')
        host_port = data.get('host_port')
        
        if not host_ip or not host_port:
            return jsonify({
                'success': False,
                'error': 'Se requieren host_ip y host_port'
            }), 400
        
        # Obtener la ruta del script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        script_path = os.path.join(script_dir, 'configurar_host_management.py')
        
        # Verificar que el script existe
        if not os.path.exists(script_path):
            return jsonify({
                'success': False,
                'error': f'Script no encontrado: {script_path}'
            }), 500
        
        # Ejecutar el script con los parámetros
        try:
            result = subprocess.run(
                [sys.executable, script_path, host_ip, host_port],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=script_dir
            )
            
            if result.returncode == 0:
                return jsonify({
                    'success': True,
                    'message': 'Flujos creados correctamente',
                    'output': result.stdout
                })
            else:
                error_msg = result.stderr if result.stderr else 'Error desconocido'
                return jsonify({
                    'success': False,
                    'error': 'Error al crear flujos',
                    'output': result.stdout,
                    'error_output': error_msg,
                    'return_code': result.returncode
                }), 500
                
        except subprocess.TimeoutExpired:
            return jsonify({
                'success': False,
                'error': 'Timeout al ejecutar el script (más de 60 segundos)'
            }), 500
            
    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500


@app.route('/api/clear_all_static_flows', methods=['POST'])
def api_clear_all_static_flows():
    """API endpoint para borrar todos los flujos estáticos de todos los switches"""
    try:
        switches = controller.get_switches()
        if not switches:
            return jsonify({
                'success': False,
                'error': 'No hay switches conectados'
            }), 400
        
        results = []
        total_success = 0
        total_failed = 0
        
        for switch in switches:
            dpid = switch.get('switchDPID', '')
            if not dpid:
                continue
            
            switch_name = get_switch_name(dpid, switch.get('inetAddress', ''))
            success = controller.clear_static_flows(dpid)
            
            if success:
                total_success += 1
                results.append({
                    'switch_dpid': dpid,
                    'switch_name': switch_name,
                    'status': 'success'
                })
            else:
                total_failed += 1
                results.append({
                    'switch_dpid': dpid,
                    'switch_name': switch_name,
                    'status': 'failed'
                })
        
        return jsonify({
            'success': True,
            'message': f'Flujos estáticos eliminados: {total_success} switches exitosos, {total_failed} fallidos',
            'results': results,
            'total_success': total_success,
            'total_failed': total_failed,
            'total_switches': len(switches)
        })
        
    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500


if __name__ == '__main__':
    print("=" * 70)
    print("Dashboard SDN - Iniciando servidor")
    print("=" * 70)
    print(f"Controlador Floodlight: {FLOODLIGHT_HOST}:{FLOODLIGHT_PORT}")
    print(f"Dashboard disponible en: http://127.0.0.1:5000")
    print("=" * 70)
    app.run(debug=True, host='0.0.0.0', port=5000)

