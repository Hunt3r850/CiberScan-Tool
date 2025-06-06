#!/usr/bin/env python3
"""
Script de validación para el módulo de escaneo de redes.

Este script realiza pruebas de validación para verificar el correcto
funcionamiento del módulo de escaneo de redes.
"""

import os
import sys
import logging
import unittest
import json
import tempfile
from unittest.mock import patch, MagicMock

# Añadir el directorio raíz al path para importar los módulos
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from modules.network_scanner import NetworkScanner, Host, Port, Service, NetworkVisualizer

class TestNetworkScanner(unittest.TestCase):
    """Pruebas unitarias para el módulo de escaneo de redes."""
    
    def setUp(self):
        """Configuración inicial para las pruebas."""
        self.scanner = NetworkScanner(log_level=logging.ERROR)
        self.test_output_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Limpieza después de las pruebas."""
        # Eliminar archivos temporales si es necesario
        pass
        
    @patch('nmap.PortScanner')
    def test_discover_hosts(self, mock_nmap):
        """Prueba la función de descubrimiento de hosts."""
        # Configurar el mock de nmap
        mock_scanner = MagicMock()
        mock_scanner.all_hosts.return_value = ['192.168.1.1', '192.168.1.2']
        mock_scanner.__getitem__.side_effect = lambda x: {
            '192.168.1.1': MagicMock(state=lambda: 'up', hostname=lambda: 'router'),
            '192.168.1.2': MagicMock(state=lambda: 'up', hostname=lambda: 'pc')
        }[x]
        mock_nmap.return_value = mock_scanner
        
        # Ejecutar la función
        hosts = self.scanner.discover_hosts('192.168.1.0/24')
        
        # Verificar resultados
        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts[0].ip_address, '192.168.1.1')
        self.assertEqual(hosts[0].hostname, 'router')
        self.assertEqual(hosts[0].status, 'up')
        
    @patch('nmap.PortScanner')
    def test_scan_ports(self, mock_nmap):
        """Prueba la función de escaneo de puertos."""
        # Configurar el mock de nmap
        mock_scanner = MagicMock()
        mock_scanner.all_hosts.return_value = ['192.168.1.1']
        mock_scanner.__getitem__.side_effect = lambda x: {
            '192.168.1.1': MagicMock(
                state=lambda: 'up',
                hostname=lambda: 'router',
                __getitem__=lambda y: {
                    'tcp': {
                        80: {'state': 'open', 'name': 'http', 'product': 'nginx', 'version': '1.18.0'},
                        22: {'state': 'open', 'name': 'ssh', 'product': 'OpenSSH', 'version': '8.2'}
                    }
                }[y] if y in ['tcp'] else {}
            )
        }[x]
        mock_nmap.return_value = mock_scanner
        
        # Ejecutar la función
        hosts = self.scanner.scan_ports('192.168.1.1', ports="22,80")
        
        # Verificar resultados
        self.assertEqual(len(hosts), 1)
        self.assertEqual(len(hosts[0].ports), 2)
        self.assertEqual(hosts[0].ports[0].number, 80)
        self.assertEqual(hosts[0].ports[0].state, 'open')
        self.assertEqual(hosts[0].ports[0].service.name, 'http')
        
    def test_save_load_results(self):
        """Prueba las funciones de guardar y cargar resultados."""
        # Crear datos de prueba
        host = Host('192.168.1.1', 'router', 'up')
        port1 = Port(80, 'tcp', 'open')
        service1 = Service('http', 'nginx', '1.18.0')
        port1.set_service(service1)
        host.add_port(port1)
        
        port2 = Port(22, 'tcp', 'open')
        service2 = Service('ssh', 'OpenSSH', '8.2')
        port2.set_service(service2)
        host.add_port(port2)
        
        # Guardar resultados
        temp_file = os.path.join(self.test_output_dir, 'test_results.json')
        self.scanner.save_results([host], temp_file)
        
        # Cargar resultados
        loaded_hosts = self.scanner.load_results(temp_file)
        
        # Verificar resultados
        self.assertEqual(len(loaded_hosts), 1)
        self.assertEqual(loaded_hosts[0].ip_address, '192.168.1.1')
        self.assertEqual(loaded_hosts[0].hostname, 'router')
        self.assertEqual(len(loaded_hosts[0].ports), 2)
        self.assertEqual(loaded_hosts[0].ports[0].service.name, 'http')
        
class TestNetworkVisualizer(unittest.TestCase):
    """Pruebas unitarias para el visualizador de redes."""
    
    def setUp(self):
        """Configuración inicial para las pruebas."""
        self.test_output_dir = tempfile.mkdtemp()
        self.visualizer = NetworkVisualizer(output_dir=self.test_output_dir, log_level=logging.ERROR)
        
    def tearDown(self):
        """Limpieza después de las pruebas."""
        # Eliminar archivos temporales si es necesario
        pass
        
    def test_create_network_map(self):
        """Prueba la creación de mapas de red."""
        # Crear datos de prueba
        host1 = Host('192.168.1.1', 'router', 'up')
        port1 = Port(80, 'tcp', 'open')
        service1 = Service('http', 'nginx', '1.18.0')
        port1.set_service(service1)
        host1.add_port(port1)
        
        host2 = Host('192.168.1.2', 'pc', 'up')
        port2 = Port(22, 'tcp', 'open')
        service2 = Service('ssh', 'OpenSSH', '8.2')
        port2.set_service(service2)
        host2.add_port(port2)
        
        # Crear mapa de red
        output_file = self.visualizer.create_network_map([host1, host2], filename="test_map.png")
        
        # Verificar que se creó el archivo
        self.assertIsNotNone(output_file)
        self.assertTrue(os.path.exists(output_file))
        
    def test_create_port_distribution(self):
        """Prueba la creación de gráficos de distribución de puertos."""
        # Crear datos de prueba
        hosts = []
        for i in range(5):
            host = Host(f'192.168.1.{i+1}', f'host{i+1}', 'up')
            
            # Añadir puertos comunes
            ports = [80, 443, 22, 21, 25, 110, 143, 3306, 5432]
            for port_num in ports[:i+1]:  # Cada host tiene un número diferente de puertos
                port = Port(port_num, 'tcp', 'open')
                service = Service(f'service{port_num}')
                port.set_service(service)
                host.add_port(port)
                
            hosts.append(host)
        
        # Crear distribución de puertos
        output_file = self.visualizer.create_port_distribution(hosts, filename="test_ports.png")
        
        # Verificar que se creó el archivo
        self.assertIsNotNone(output_file)
        self.assertTrue(os.path.exists(output_file))
        
    def test_generate_report(self):
        """Prueba la generación de informes completos."""
        # Crear datos de prueba
        hosts = []
        for i in range(3):
            host = Host(f'192.168.1.{i+1}', f'host{i+1}', 'up')
            
            # Añadir puertos y servicios
            port1 = Port(80, 'tcp', 'open')
            service1 = Service('http', 'nginx', '1.18.0')
            port1.set_service(service1)
            host.add_port(port1)
            
            port2 = Port(22, 'tcp', 'open')
            service2 = Service('ssh', 'OpenSSH', '8.2')
            port2.set_service(service2)
            host.add_port(port2)
            
            # Añadir información de OS
            host.set_os_info({'name': f'OS{i+1}', 'accuracy': '90'})
            
            hosts.append(host)
        
        # Generar informe
        report_files = self.visualizer.generate_report(hosts)
        
        # Verificar que se crearon los archivos
        self.assertGreater(len(report_files), 0)
        for file_path in report_files.values():
            self.assertTrue(os.path.exists(file_path))

if __name__ == '__main__':
    unittest.main()
