#!/usr/bin/env python3
"""
Script de prueba para validar la sintaxis correcta de goto_table en Floodlight 1.2
y verificar si soporta múltiples tablas en el Static Flow Pusher.
"""

import requests
import json
import sys
import time
from typing import Dict, Optional, Tuple


class FloodlightController:
    """Clase para interactuar con la API REST de Floodlight"""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.base_url = f"http://{host}:{port}"
        self.headers = {'Content-Type': 'application/json'}
    
    def get_switches(self) -> list:
        """Obtiene la lista de switches conectados"""
        try:
            url = f"{self.base_url}/wm/core/controller/switches/json"
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException:
            return []
    
    def get_switch_dpid_by_ip(self, ip_address: str) -> Optional[str]:
        """Obtiene el DPID de un switch por su dirección IP"""
        switches = self.get_switches()
        
        def search_ip_in_dict(data, target_ip):
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
            if search_ip_in_dict(switch, ip_address):
                return switch.get('switchDPID')
            inet_address = switch.get('inetAddress', '')
            if ip_address in str(inet_address):
                return switch.get('switchDPID')
        
        return None
    
    def add_flow(self, flow: Dict) -> Tuple[bool, str]:
        """
        Añade un flujo estático al controlador
        
        Returns:
            (True/False, mensaje de error o éxito)
        """
        try:
            url = f"{self.base_url}/wm/staticflowpusher/json"
            
            flow_copy = flow.copy()
            if 'cookie' not in flow_copy:
                flow_copy['cookie'] = '0'
            if 'active' not in flow_copy:
                flow_copy['active'] = 'true'
            
            response = requests.post(url, data=json.dumps(flow_copy), 
                                    headers=self.headers, timeout=5)
            
            if response.status_code == 200:
                try:
                    result = response.json()
                    status = result.get('status', '')
                    if status in ['Entry pushed', 'success']:
                        return True, "Éxito"
                    else:
                        return True, f"Status: {status}"
                except (ValueError, KeyError):
                    return True, "Éxito (sin JSON)"
            else:
                try:
                    error_msg = response.json()
                    return False, f"Error {response.status_code}: {json.dumps(error_msg)}"
                except:
                    return False, f"Error {response.status_code}: {response.text}"
                    
        except requests.exceptions.RequestException as e:
            return False, f"Excepción: {e}"
    
    def get_flow(self, switch_dpid: str, flow_name: str) -> Optional[Dict]:
        """Obtiene un flujo específico del switch"""
        try:
            url = f"{self.base_url}/wm/staticflowpusher/list/{switch_dpid}/json"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                flows = data.get(switch_dpid, [])
                for flow_entry in flows:
                    if flow_name in flow_entry:
                        return flow_entry[flow_name]
            return None
        except:
            return None
    
    def delete_flow(self, switch_dpid: str, flow_name: str) -> bool:
        """Elimina un flujo específico"""
        try:
            url = f"{self.base_url}/wm/staticflowpusher/delete/{switch_dpid}/{flow_name}/json"
            response = requests.delete(url, timeout=5)
            return response.status_code == 200
        except:
            return False


def test_goto_table_syntax(controller: FloodlightController, switch_dpid: str, test_num: int, flow_def: Dict, description: str):
    """Prueba una sintaxis específica de goto_table"""
    print(f"\n{'='*70}")
    print(f"PRUEBA {test_num}: {description}")
    print(f"{'='*70}")
    print(f"JSON enviado:")
    print(json.dumps(flow_def, indent=2))
    
    # Eliminar flujo anterior si existe
    controller.delete_flow(switch_dpid, flow_def['name'])
    time.sleep(0.5)
    
    # Intentar agregar el flujo
    success, message = controller.add_flow(flow_def)
    print(f"\nResultado: {'✓ ÉXITO' if success else '✗ FALLO'}")
    print(f"Mensaje: {message}")
    
    if success:
        # Esperar un momento para que se procese
        time.sleep(1)
        
        # Obtener el flujo instalado
        installed_flow = controller.get_flow(switch_dpid, flow_def['name'])
        if installed_flow:
            print(f"\nFlujo instalado en Floodlight:")
            print(json.dumps(installed_flow, indent=2))
            
            # Verificar si tiene goto_table
            instructions = installed_flow.get('instructions', {})
            if 'instruction_goto_table' in instructions:
                print(f"\n✓✓✓ ENCONTRADO: instruction_goto_table")
                table_id = instructions.get('instruction_goto_table', {}).get('table_id', 'N/A')
                print(f"   Table ID: {table_id}")
                return True
            elif 'instruction_apply_actions' in instructions:
                actions = instructions.get('instruction_apply_actions', {})
                if 'none' in actions and actions['none'] == 'drop':
                    print(f"\n✗✗✗ PROBLEMA: Se convirtió a drop")
                else:
                    print(f"\n⚠ ADVERTENCIA: Se convirtió a instruction_apply_actions")
                    print(f"   Contenido: {actions}")
            else:
                print(f"\n⚠ ADVERTENCIA: Estructura de instructions inesperada")
        else:
            print(f"\n⚠ No se pudo recuperar el flujo instalado")
    
    return False


def main():
    print("=" * 70)
    print("SCRIPT DE PRUEBA: Validación de goto_table en Floodlight 1.2")
    print("=" * 70)
    
    # Inicializar controlador
    controller = FloodlightController(host="127.0.0.1", port=8080)
    
    # Verificar conectividad
    print("\n[1] Verificando conectividad...")
    switches = controller.get_switches()
    if not switches:
        print("ERROR: No se pudo conectar al controlador")
        sys.exit(1)
    
    print(f"✓ Controlador conectado. Switches: {len(switches)}")
    
    # Obtener SW3
    print("\n[2] Obteniendo SW3...")
    sw3_dpid = controller.get_switch_dpid_by_ip("192.168.200.147")
    if not sw3_dpid:
        print("ERROR: No se encontró SW3")
        # Intentar usar el primer switch disponible
        if switches:
            sw3_dpid = switches[0].get('switchDPID')
            print(f"Usando primer switch disponible: {sw3_dpid}")
        else:
            sys.exit(1)
    else:
        print(f"✓ SW3 encontrado: {sw3_dpid}")
    
    # Definir diferentes sintaxis para probar
    test_flows = [
        {
            "description": "Sintaxis 1: actions con goto_table:1 (como ovs-ofctl)",
            "flow": {
                "switch": sw3_dpid,
                "name": "test_goto_table_1",
                "table": "0",
                "priority": "0",
                "actions": "goto_table:1"
            }
        },
        {
            "description": "Sintaxis 2: instructions con instruction_goto_table (estructura completa)",
            "flow": {
                "switch": sw3_dpid,
                "name": "test_goto_table_2",
                "table": "0",
                "priority": "0",
                "instructions": {
                    "instruction_goto_table": {
                        "table_id": "1"
                    }
                }
            }
        },
        {
            "description": "Sintaxis 3: instructions con instruction_goto_table (valor directo)",
            "flow": {
                "switch": sw3_dpid,
                "name": "test_goto_table_3",
                "table": "0",
                "priority": "0",
                "instructions": {
                    "instruction_goto_table": "1"
                }
            }
        },
        {
            "description": "Sintaxis 4: instructions como lista con GOTO_TABLE",
            "flow": {
                "switch": sw3_dpid,
                "name": "test_goto_table_4",
                "table": "0",
                "priority": "0",
                "instructions": [
                    {
                        "type": "GOTO_TABLE",
                        "table_id": 1
                    }
                ]
            }
        },
        {
            "description": "Sintaxis 5: goto_table como campo directo",
            "flow": {
                "switch": sw3_dpid,
                "name": "test_goto_table_5",
                "table": "0",
                "priority": "0",
                "goto_table": "1"
            }
        },
        {
            "description": "Sintaxis 6: actions con resubmit (Open vSwitch)",
            "flow": {
                "switch": sw3_dpid,
                "name": "test_goto_table_6",
                "table": "0",
                "priority": "0",
                "actions": "resubmit(,1)"
            }
        }
    ]
    
    print(f"\n[3] Probando {len(test_flows)} sintaxis diferentes...")
    print("NOTA: Cada prueba eliminará el flujo anterior antes de crear uno nuevo")
    
    successful_tests = []
    
    for i, test in enumerate(test_flows, 1):
        result = test_goto_table_syntax(
            controller, 
            sw3_dpid, 
            i, 
            test["flow"], 
            test["description"]
        )
        
        if result:
            successful_tests.append((i, test["description"]))
        
        # Esperar entre pruebas
        time.sleep(1)
    
    # Resumen
    print("\n" + "=" * 70)
    print("RESUMEN")
    print("=" * 70)
    
    if successful_tests:
        print(f"\n✓ Sintaxis que funcionaron ({len(successful_tests)}):")
        for test_num, desc in successful_tests:
            print(f"  - Prueba {test_num}: {desc}")
    else:
        print("\n✗ Ninguna sintaxis funcionó correctamente")
        print("\nCONCLUSIÓN:")
        print("  Floodlight 1.2 Static Flow Pusher probablemente NO soporta")
        print("  goto_table directamente. Puede ser necesario:")
        print("  1. Usar ovs-ofctl directamente")
        print("  2. Actualizar a una versión más reciente de Floodlight")
        print("  3. Usar una API diferente de Floodlight")
    
    # Limpiar flujos de prueba
    print("\n[4] Limpiando flujos de prueba...")
    for test in test_flows:
        controller.delete_flow(sw3_dpid, test["flow"]["name"])
    print("✓ Limpieza completada")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOperación cancelada por el usuario.")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR INESPERADO: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

