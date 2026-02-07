#!/usr/bin/env python3
"""
Script de validación simplificado para el módulo de escaneo de redes.

Este script realiza pruebas básicas para verificar la estructura
y funcionalidad del módulo de escaneo de redes sin depender de
operaciones de red reales.
"""

import os
import sys
import logging
import unittest
from unittest.mock import patch, MagicMock

# Añadir el directorio raíz al path para importar los módulos
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from modules.network_scanner import Host, Port, Service

class TestNetworkScannerClasses(unittest.TestCase):
    """Pruebas unitarias para las clases básicas del módulo de escaneo de redes."""
    
    def test_host_class(self):
        """Prueba la clase Host."""
        # Crear un host
        host = Host('192.168.1.1', 'router', 'up')
        
        # Verificar atributos
        self.assertEqual(host.ip_address, '192.168.1.1')
        self.assertEqual(host.hostname, 'router')
        self.assertEqual(host.status, 'up')
        self.assertEqual(len(host.ports), 0)
        
        # Verificar método to_dict
        host_dict = host.to_dict()
        self.assertEqual(host_dict['ip_address'], '192.168.1.1')
        self.assertEqual(host_dict['hostname'], 'router')
        self.assertEqual(host_dict['status'], 'up')
        
    def test_port_class(self):
        """Prueba la clase Port."""
        # Crear un puerto
        port = Port(80, 'tcp', 'open')
        
        # Verificar atributos
        self.assertEqual(port.number, 80)
        self.assertEqual(port.protocol, 'tcp')
        self.assertEqual(port.state, 'open')
        self.assertIsNone(port.service)
        
        # Verificar método to_dict
        port_dict = port.to_dict()
        self.assertEqual(port_dict['number'], 80)
        self.assertEqual(port_dict['protocol'], 'tcp')
        self.assertEqual(port_dict['state'], 'open')
        self.assertIsNone(port_dict['service'])
        
    def test_service_class(self):
        """Prueba la clase Service."""
        # Crear un servicio
        service = Service('http', 'nginx', '1.18.0')
        
        # Verificar atributos
        self.assertEqual(service.name, 'http')
        self.assertEqual(service.product, 'nginx')
        self.assertEqual(service.version, '1.18.0')
        
        # Añadir información extra
        service.add_info('cpe', 'cpe:/a:nginx:nginx:1.18.0')
        
        # Verificar método to_dict
        service_dict = service.to_dict()
        self.assertEqual(service_dict['name'], 'http')
        self.assertEqual(service_dict['product'], 'nginx')
        self.assertEqual(service_dict['version'], '1.18.0')
        self.assertEqual(service_dict['extra_info']['cpe'], 'cpe:/a:nginx:nginx:1.18.0')
        
    def test_host_port_service_integration(self):
        """Prueba la integración entre Host, Port y Service."""
        # Crear objetos
        host = Host('192.168.1.1', 'router', 'up')
        port = Port(80, 'tcp', 'open')
        service = Service('http', 'nginx', '1.18.0')
        
        # Establecer relaciones
        port.set_service(service)
        host.add_port(port)
        
        # Verificar relaciones
        self.assertEqual(len(host.ports), 1)
        self.assertEqual(host.ports[0].number, 80)
        self.assertEqual(host.ports[0].service.name, 'http')
        
        # Verificar conversión a diccionario
        host_dict = host.to_dict()
        self.assertEqual(len(host_dict['ports']), 1)
        self.assertEqual(host_dict['ports'][0]['number'], 80)
        self.assertEqual(host_dict['ports'][0]['service']['name'], 'http')

if __name__ == '__main__':
    unittest.main()
