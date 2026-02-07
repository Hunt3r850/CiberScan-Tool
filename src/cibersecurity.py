#!/usr/bin/env python3
"""
Script principal para la herramienta de ciberseguridad.

Este script inicializa la aplicación y proporciona una interfaz
para acceder a los diferentes módulos de la herramienta.
"""

import os
import sys
import logging
import argparse
import json
from datetime import datetime

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("CiberSecurity")

def setup_directories():
    """
    Crea los directorios necesarios para la aplicación.
    """
    dirs = ['output', 'reports', 'logs', 'data']
    for directory in dirs:
        if not os.path.exists(directory):
            os.makedirs(directory)
            logger.info(f"Directorio creado: {directory}")

def network_scan(args):
    """
    Ejecuta el módulo de escaneo de redes.
    """
    from modules.network_scanner import NetworkScanner, NetworkVisualizer
    
    logger.info(f"Iniciando escaneo de red en {args.target} (modo: {args.mode})")
    
    # Inicializar escáner
    scanner = NetworkScanner()
    
    # Realizar escaneo
    hosts = scanner.scan_network(args.target, scan_mode=args.mode)
    
    # Guardar resultados
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_file = os.path.join('output', f'network_scan_{timestamp}.json')
    scanner.save_results(hosts, results_file)
    
    # Generar visualizaciones
    logger.info("Generando visualizaciones")
    visualizer = NetworkVisualizer(output_dir='output')
    report_files = visualizer.generate_report(hosts)
    
    # Mostrar resumen
    logger.info(f"Escaneo completado. Se encontraron {len(hosts)} hosts.")
    up_hosts = sum(1 for host in hosts if host.status == "up")
    logger.info(f"Hosts activos: {up_hosts}")
    
    total_ports = sum(len(host.ports) for host in hosts)
    logger.info(f"Total de puertos encontrados: {total_ports}")
    
    # Mostrar archivos generados
    logger.info(f"Resultados guardados en: {results_file}")
    for name, path in report_files.items():
        logger.info(f"Visualización '{name}' guardada en: {path}")
    
    return results_file, report_files

def vulnerability_scan(args):
    """
    Ejecuta el módulo de análisis de vulnerabilidades.
    """
    logger.info("Módulo de análisis de vulnerabilidades no implementado aún")
    return None

def web_directory_scan(args):
    """
    Ejecuta el módulo de escaneo web de directorios.
    """
    logger.info("Módulo de escaneo web de directorios no implementado aún")
    return None

def web_vulnerability_scan(args):
    """
    Ejecuta el módulo de análisis de vulnerabilidades web.
    """
    logger.info("Módulo de análisis de vulnerabilidades web no implementado aún")
    return None

def main():
    """
    Función principal que maneja los argumentos de línea de comandos
    y ejecuta los módulos correspondientes.
    """
    # Crear parser principal
    parser = argparse.ArgumentParser(
        description='Herramienta de Ciberseguridad',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python cibersecurity.py network 192.168.1.0/24 --mode fast
  python cibersecurity.py vulnerability 192.168.1.10
  python cibersecurity.py webdir http://example.com --wordlist common.txt
  python cibersecurity.py webvuln http://example.com
        """
    )
    
    # Crear subparsers para cada módulo
    subparsers = parser.add_subparsers(dest='module', help='Módulo a ejecutar')
    
    # Parser para el módulo de escaneo de redes
    network_parser = subparsers.add_parser('network', help='Escaneo de redes')
    network_parser.add_argument('target', help='Objetivo del escaneo (IP, rango o subred)')
    network_parser.add_argument('--mode', choices=['fast', 'normal', 'comprehensive'], 
                              default='normal', help='Modo de escaneo')
    
    # Parser para el módulo de análisis de vulnerabilidades
    vuln_parser = subparsers.add_parser('vulnerability', help='Análisis de vulnerabilidades')
    vuln_parser.add_argument('target', help='Objetivo del análisis')
    
    # Parser para el módulo de escaneo web de directorios
    webdir_parser = subparsers.add_parser('webdir', help='Escaneo web de directorios')
    webdir_parser.add_argument('target', help='URL objetivo')
    webdir_parser.add_argument('--wordlist', help='Diccionario a utilizar')
    
    # Parser para el módulo de análisis de vulnerabilidades web
    webvuln_parser = subparsers.add_parser('webvuln', help='Análisis de vulnerabilidades web')
    webvuln_parser.add_argument('target', help='URL objetivo')
    
    # Parsear argumentos
    args = parser.parse_args()
    
    # Verificar que se haya especificado un módulo
    if not args.module:
        parser.print_help()
        return
    
    # Crear directorios necesarios
    setup_directories()
    
    # Ejecutar el módulo correspondiente
    if args.module == 'network':
        network_scan(args)
    elif args.module == 'vulnerability':
        vulnerability_scan(args)
    elif args.module == 'webdir':
        web_directory_scan(args)
    elif args.module == 'webvuln':
        web_vulnerability_scan(args)

if __name__ == "__main__":
    main()
