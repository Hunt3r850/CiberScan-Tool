#!/usr/bin/env python3
"""
Script de prueba para el módulo de escaneo de redes.

Este script demuestra el uso del módulo de escaneo de redes para descubrir hosts,
escanear puertos y visualizar los resultados.
"""

import os
import sys
import logging
import argparse
import json

# Añadir el directorio raíz al path para importar los módulos
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from modules.network_scanner import NetworkScanner, NetworkVisualizer

def main():
    # Configurar logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger("NetworkScannerTest")
    
    # Parsear argumentos
    parser = argparse.ArgumentParser(description='Herramienta de escaneo de redes')
    parser.add_argument('target', help='Objetivo del escaneo (IP, rango o subred)')
    parser.add_argument('--mode', choices=['fast', 'normal', 'comprehensive'], 
                        default='normal', help='Modo de escaneo')
    parser.add_argument('--output', default='./output', help='Directorio de salida')
    parser.add_argument('--save', default='scan_results.json', help='Archivo para guardar resultados')
    args = parser.parse_args()
    
    # Crear directorio de salida si no existe
    if not os.path.exists(args.output):
        os.makedirs(args.output)
    
    # Inicializar escáner
    logger.info(f"Iniciando escaneo de red en {args.target} (modo: {args.mode})")
    scanner = NetworkScanner()
    
    # Realizar escaneo
    hosts = scanner.scan_network(args.target, scan_mode=args.mode)
    
    # Guardar resultados
    results_file = os.path.join(args.output, args.save)
    scanner.save_results(hosts, results_file)
    
    # Generar visualizaciones
    logger.info("Generando visualizaciones")
    visualizer = NetworkVisualizer(output_dir=args.output)
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

if __name__ == "__main__":
    main()
