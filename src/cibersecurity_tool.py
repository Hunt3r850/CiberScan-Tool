#!/usr/bin/env python3
"""
Script principal de automatización para la herramienta de ciberseguridad.

Este script integra todos los módulos desarrollados y proporciona una interfaz
unificada para realizar análisis de ciberseguridad completos.
"""

import os
import sys
import logging
import argparse
import json
import datetime
import time
import concurrent.futures
from pathlib import Path

# Añadir el directorio raíz al path para importar los módulos
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Importar módulos del proyecto
from src.modules.network_scanner.scanner import NetworkScanner
from src.modules.network_scanner.visualizer import NetworkVisualizer
from src.modules.vulnerability_scanner.scanner import VulnerabilityScanner
from src.modules.vulnerability_scanner.reporter import VulnerabilityReporter
from src.modules.web_directory_scanner.scanner import DirectoryScanner
from src.modules.web_directory_scanner.wordlist import WordlistManager
from src.modules.web_directory_scanner.reporter import DirectoryReporter
from src.modules.web_vulnerability_scanner.scanner import WebVulnerabilityScanner
from src.modules.web_vulnerability_scanner.reporter import WebVulnerabilityReporter

class CibersecurityTool:
    def __init__(self, output_dir="./output", log_level=logging.INFO):
        """
        Inicializa la herramienta de ciberseguridad.
        
        Args:
            output_dir (str): Directorio para guardar los resultados
            log_level (int): Nivel de logging
        """
        self.output_dir = output_dir
        self.logger = self._setup_logger(log_level)
        
        # Crear directorio de salida si no existe
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        # Inicializar componentes
        self.network_scanner = None
        self.vulnerability_scanner = None
        self.directory_scanner = None
        self.web_vulnerability_scanner = None
        
        # Resultados
        self.network_results = {}
        self.vulnerability_results = {}
        self.directory_results = []
        self.web_vulnerability_results = {}
        
    def _setup_logger(self, log_level):
        """
        Configura el logger para la herramienta.
        
        Args:
            log_level (int): Nivel de logging
            
        Returns:
            Logger: Objeto logger configurado
        """
        logger = logging.getLogger("CibersecurityTool")
        logger.setLevel(log_level)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
            # También añadir un handler para archivo
            log_file = os.path.join(self.output_dir, "cibersecurity_tool.log")
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            
        return logger
        
    def initialize_components(self):
        """
        Inicializa todos los componentes de la herramienta.
        
        Returns:
            bool: True si todos los componentes se inicializaron correctamente
        """
        try:
            self.logger.info("Inicializando componentes...")
            
            # Inicializar escáner de redes
            self.network_scanner = NetworkScanner()
            
            # Inicializar escáner de vulnerabilidades
            self.vulnerability_scanner = VulnerabilityScanner()
            
            # Inicializar escáner de directorios web
            wordlists_dir = os.path.join(os.path.dirname(__file__), '../data/wordlists')
            if not os.path.exists(wordlists_dir):
                os.makedirs(wordlists_dir)
            wordlist_manager = WordlistManager(wordlists_dir=wordlists_dir)
            self.directory_scanner = DirectoryScanner(wordlist_manager=wordlist_manager)
            
            # Inicializar escáner de vulnerabilidades web
            self.web_vulnerability_scanner = WebVulnerabilityScanner()
            
            self.logger.info("Todos los componentes inicializados correctamente")
            return True
            
        except Exception as e:
            self.logger.error(f"Error al inicializar componentes: {str(e)}")
            return False
            
    def scan_network(self, target, scan_type="fast", ports=None):
        """
        Realiza un escaneo de red.
        
        Args:
            target (str): Objetivo a escanear (IP, rango de IPs o dominio)
            scan_type (str): Tipo de escaneo ('fast', 'normal', 'deep')
            ports (str): Puertos a escanear (ej. '22,80,443' o '1-1000')
            
        Returns:
            dict: Resultados del escaneo
        """
        self.logger.info(f"Iniciando escaneo de red en {target}")
        
        try:
            # Configurar escaneo según el tipo
            if scan_type == "fast":
                self.network_scanner.set_scan_speed("fast")
                if not ports:
                    ports = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
            elif scan_type == "normal":
                self.network_scanner.set_scan_speed("normal")
                if not ports:
                    ports = "1-1000"
            elif scan_type == "deep":
                self.network_scanner.set_scan_speed("slow")
                if not ports:
                    ports = "1-65535"
                    
            # Realizar escaneo
            self.network_results = self.network_scanner.scan(target, ports)
            
            # Guardar resultados
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            results_file = os.path.join(self.output_dir, f"network_scan_{timestamp}.json")
            self.network_scanner.save_results(self.network_results, results_file)
            
            # Generar visualización
            visualizer = NetworkVisualizer()
            network_map = os.path.join(self.output_dir, f"network_map_{timestamp}.png")
            visualizer.generate_network_map(self.network_results, network_map)
            
            self.logger.info(f"Escaneo de red completado. Resultados guardados en {results_file}")
            return self.network_results
            
        except Exception as e:
            self.logger.error(f"Error durante el escaneo de red: {str(e)}")
            return {}
            
    def scan_vulnerabilities(self, hosts=None):
        """
        Realiza un análisis de vulnerabilidades.
        
        Args:
            hosts (list): Lista de hosts a analizar (si es None, usa los resultados del escaneo de red)
            
        Returns:
            dict: Resultados del análisis de vulnerabilidades
        """
        self.logger.info("Iniciando análisis de vulnerabilidades")
        
        try:
            # Si no se proporcionan hosts, usar los del escaneo de red
            if not hosts and self.network_results:
                hosts = []
                for host_ip, host_data in self.network_results.items():
                    host_info = {
                        'ip': host_ip,
                        'ports': [port['port'] for port in host_data.get('ports', [])]
                    }
                    hosts.append(host_info)
                    
            if not hosts:
                self.logger.warning("No se proporcionaron hosts para el análisis de vulnerabilidades")
                return {}
                
            # Realizar análisis de vulnerabilidades
            self.vulnerability_results = {}
            for host in hosts:
                host_ip = host['ip']
                self.logger.info(f"Analizando vulnerabilidades en {host_ip}")
                
                # Analizar vulnerabilidades para cada puerto
                host_vulns = []
                for port in host.get('ports', []):
                    vulns = self.vulnerability_scanner.scan_host_port(host_ip, port)
                    host_vulns.extend(vulns)
                    
                self.vulnerability_results[host_ip] = host_vulns
                
            # Guardar resultados
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            results_file = os.path.join(self.output_dir, f"vulnerability_scan_{timestamp}.json")
            self.vulnerability_scanner.save_results(self.vulnerability_results, results_file)
            
            # Generar informe
            reporter = VulnerabilityReporter(output_dir=self.output_dir)
            report_files = reporter.generate_complete_report(self.vulnerability_results)
            
            self.logger.info(f"Análisis de vulnerabilidades completado. Resultados guardados en {results_file}")
            return self.vulnerability_results
            
        except Exception as e:
            self.logger.error(f"Error durante el análisis de vulnerabilidades: {str(e)}")
            return {}
            
    def scan_web_directories(self, url, wordlist=None, extensions=None, threads=10):
        """
        Realiza un escaneo de directorios web.
        
        Args:
            url (str): URL base del sitio web
            wordlist (str): Nombre o ruta del diccionario a utilizar
            extensions (list): Lista de extensiones a probar
            threads (int): Número de hilos para escaneo paralelo
            
        Returns:
            list: Resultados del escaneo
        """
        self.logger.info(f"Iniciando escaneo de directorios web en {url}")
        
        try:
            # Configurar extensiones
            if not extensions:
                extensions = ["", ".php", ".html", ".js", ".txt", ".xml", ".json", ".bak", ".old", ".backup"]
                
            # Configurar diccionario
            if not wordlist:
                wordlist = "common.txt"
                
                # Verificar si existe el diccionario, si no, crear uno básico
                wordlists_dir = os.path.join(os.path.dirname(__file__), '../data/wordlists')
                common_wordlist = os.path.join(wordlists_dir, 'common.txt')
                if not os.path.exists(common_wordlist):
                    self.logger.info("Creando diccionario básico")
                    with open(common_wordlist, 'w') as f:
                        f.write('\n'.join([
                            'admin', 'login', 'wp-admin', 'administrator', 'phpmyadmin',
                            'dashboard', 'wp-content', 'upload', 'images', 'img',
                            'css', 'js', 'api', 'backup', 'db', 'sql', 'dev',
                            'test', 'demo', 'staging', 'beta', 'old', 'new',
                            'wp-includes', 'include', 'includes', 'temp', 'tmp',
                            'download', 'downloads', 'assets', 'static', 'media',
                            'config', 'configuration', 'setup', 'install', 'log',
                            'logs', 'error', 'debug', 'file', 'files', 'upload',
                            'uploads', 'private', 'public', 'secret', 'hidden'
                        ]))
                
            # Realizar escaneo
            self.directory_results = self.directory_scanner.scan_with_wordlist(
                url, 
                self.directory_scanner.wordlist_manager.load_wordlist(wordlist),
                extensions=extensions,
                threads=threads
            )
            
            # Guardar resultados
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            results_file = os.path.join(self.output_dir, f"directory_scan_{timestamp}.json")
            self.directory_scanner.save_results(self.directory_results, results_file)
            
            # Generar informe
            reporter = DirectoryReporter(output_dir=self.output_dir)
            report_files = reporter.generate_complete_report(self.directory_results, url)
            
            self.logger.info(f"Escaneo de directorios web completado. Resultados guardados en {results_file}")
            return self.directory_results
            
        except Exception as e:
            self.logger.error(f"Error durante el escaneo de directorios web: {str(e)}")
            return []
            
    def scan_web_vulnerabilities(self, url, crawl_depth=1, max_urls=10, scan_types=None):
        """
        Realiza un análisis de vulnerabilidades web.
        
        Args:
            url (str): URL del sitio web
            crawl_depth (int): Profundidad de rastreo
            max_urls (int): Número máximo de URLs a analizar
            scan_types (list): Tipos de escaneo a realizar
            
        Returns:
            dict: Resultados del análisis
        """
        self.logger.info(f"Iniciando análisis de vulnerabilidades web en {url}")
        
        try:
            # Configurar tipos de escaneo
            if not scan_types:
                scan_types = ['xss', 'sqli', 'open_redirect', 'header_injection']
                
            # Realizar escaneo
            self.web_vulnerability_results = self.web_vulnerability_scanner.scan_site(
                base_url=url,
                crawl_depth=crawl_depth,
                max_urls=max_urls,
                scan_types=scan_types
            )
            
            # Guardar resultados
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            results_file = os.path.join(self.output_dir, f"web_vulnerability_scan_{timestamp}.json")
            self.web_vulnerability_scanner.save_results(self.web_vulnerability_results, results_file)
            
            # Generar informe
            reporter = WebVulnerabilityReporter(output_dir=self.output_dir)
            report_files = reporter.generate_complete_report(self.web_vulnerability_results)
            
            self.logger.info(f"Análisis de vulnerabilidades web completado. Resultados guardados en {results_file}")
            return self.web_vulnerability_results
            
        except Exception as e:
            self.logger.error(f"Error durante el análisis de vulnerabilidades web: {str(e)}")
            return {}
            
    def run_complete_scan(self, target, web_url=None, scan_type="normal", ports=None, 
                         wordlist=None, extensions=None, threads=10, 
                         crawl_depth=1, max_urls=10, scan_types=None):
        """
        Ejecuta un escaneo completo de ciberseguridad.
        
        Args:
            target (str): Objetivo a escanear (IP, rango de IPs o dominio)
            web_url (str): URL del sitio web (si es diferente del target)
            scan_type (str): Tipo de escaneo de red ('fast', 'normal', 'deep')
            ports (str): Puertos a escanear
            wordlist (str): Nombre o ruta del diccionario para escaneo de directorios
            extensions (list): Lista de extensiones para escaneo de directorios
            threads (int): Número de hilos para escaneo paralelo
            crawl_depth (int): Profundidad de rastreo para análisis de vulnerabilidades web
            max_urls (int): Número máximo de URLs a analizar
            scan_types (list): Tipos de escaneo de vulnerabilidades web
            
        Returns:
            dict: Resultados completos del escaneo
        """
        self.logger.info(f"Iniciando escaneo completo de ciberseguridad en {target}")
        
        # Crear directorio para este escaneo
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_dir = os.path.join(self.output_dir, f"complete_scan_{timestamp}")
        os.makedirs(scan_dir)
        
        # Actualizar directorio de salida para este escaneo
        original_output_dir = self.output_dir
        self.output_dir = scan_dir
        
        results = {
            "timestamp": timestamp,
            "target": target,
            "web_url": web_url or target,
            "scan_type": scan_type,
            "network_scan": {},
            "vulnerability_scan": {},
            "directory_scan": {},
            "web_vulnerability_scan": {}
        }
        
        try:
            # Paso 1: Escaneo de red
            self.logger.info("PASO 1: Escaneo de red")
            network_results = self.scan_network(target, scan_type, ports)
            results["network_scan"] = {
                "status": "completed" if network_results else "failed",
                "hosts_found": len(network_results) if network_results else 0,
                "results_file": os.path.join(scan_dir, f"network_scan_{timestamp}.json")
            }
            
            # Paso 2: Análisis de vulnerabilidades
            self.logger.info("PASO 2: Análisis de vulnerabilidades")
            vulnerability_results = self.scan_vulnerabilities()
            results["vulnerability_scan"] = {
                "status": "completed" if vulnerability_results else "failed",
                "vulnerabilities_found": sum(len(vulns) for vulns in vulnerability_results.values()) if vulnerability_results else 0,
                "results_file": os.path.join(scan_dir, f"vulnerability_scan_{timestamp}.json")
            }
            
            # Determinar URL web si no se proporcionó
            if not web_url:
                # Buscar servidores web en los resultados del escaneo de red
                web_servers = []
                for host_ip, host_data in network_results.items():
                    for port in host_data.get('ports', []):
                        if port.get('service') in ['http', 'https'] or port.get('port') in [80, 443, 8080, 8443]:
                            protocol = 'https' if port.get('port') in [443, 8443] else 'http'
                            web_servers.append(f"{protocol}://{host_ip}:{port.get('port')}")
                
                if web_servers:
                    web_url = web_servers[0]
                    self.logger.info(f"Servidor web detectado automáticamente: {web_url}")
                else:
                    web_url = f"http://{target}"
                    self.logger.warning(f"No se detectaron servidores web. Usando URL por defecto: {web_url}")
            
            # Paso 3: Escaneo de directorios web
            if web_url:
                self.logger.info(f"PASO 3: Escaneo de directorios web en {web_url}")
                directory_results = self.scan_web_directories(web_url, wordlist, extensions, threads)
                results["directory_scan"] = {
                    "status": "completed" if directory_results else "failed",
                    "directories_found": len([r for r in directory_results if r.is_success()]) if directory_results else 0,
                    "results_file": os.path.join(scan_dir, f"directory_scan_{timestamp}.json")
                }
                
                # Paso 4: Análisis de vulnerabilidades web
                self.logger.info(f"PASO 4: Análisis de vulnerabilidades web en {web_url}")
                web_vulnerability_results = self.scan_web_vulnerabilities(web_url, crawl_depth, max_urls, scan_types)
                results["web_vulnerability_scan"] = {
                    "status": "completed" if web_vulnerability_results else "failed",
                    "vulnerabilities_found": sum(len(vulns) for vulns in web_vulnerability_results.values()) if web_vulnerability_results else 0,
                    "results_file": os.path.join(scan_dir, f"web_vulnerability_scan_{timestamp}.json")
                }
            else:
                self.logger.warning("No se pudo determinar una URL web para escanear")
                results["directory_scan"]["status"] = "skipped"
                results["web_vulnerability_scan"]["status"] = "skipped"
            
            # Generar informe final
            self.generate_final_report(results, scan_dir)
            
            self.logger.info(f"Escaneo completo finalizado. Resultados guardados en {scan_dir}")
            
        except Exception as e:
            self.logger.error(f"Error durante el escaneo completo: {str(e)}")
            results["error"] = str(e)
            
        finally:
            # Restaurar directorio de salida original
            self.output_dir = original_output_dir
            
        return results
        
    def generate_final_report(self, results, output_dir):
        """
        Genera un informe final consolidado.
        
        Args:
            results (dict): Resultados del escaneo completo
            output_dir (str): Directorio de salida
            
        Returns:
            str: Ruta del informe generado
        """
        self.logger.info("Generando informe final consolidado")
        
        # Guardar resultados en JSON
        results_file = os.path.join(output_dir, "complete_scan_results.json")
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=4)
            
        # Generar informe HTML
        html_report = os.path.join(output_dir, "complete_scan_report.html")
        
        # Cargar datos detallados si están disponibles
        network_data = {}
        vulnerability_data = {}
        directory_data = []
        web_vulnerability_data = {}
        
        try:
            if os.path.exists(results["network_scan"].get("results_file", "")):
                with open(results["network_scan"]["results_file"], 'r') as f:
                    network_data = json.load(f)
        except Exception as e:
            self.logger.error(f"Error al cargar datos de red: {str(e)}")
            
        try:
            if os.path.exists(results["vulnerability_scan"].get("results_file", "")):
                with open(results["vulnerability_scan"]["results_file"], 'r') as f:
                    vulnerability_data = json.load(f)
        except Exception as e:
            self.logger.error(f"Error al cargar datos de vulnerabilidades: {str(e)}")
            
        try:
            if os.path.exists(results["directory_scan"].get("results_file", "")):
                with open(results["directory_scan"]["results_file"], 'r') as f:
                    directory_data = json.load(f)
        except Exception as e:
            self.logger.error(f"Error al cargar datos de directorios: {str(e)}")
            
        try:
            if os.path.exists(results["web_vulnerability_scan"].get("results_file", "")):
                with open(results["web_vulnerability_scan"]["results_file"], 'r') as f:
                    web_vulnerability_data = json.load(f)
        except Exception as e:
            self.logger.error(f"Error al cargar datos de vulnerabilidades web: {str(e)}")
        
        # Generar HTML
        with open(html_report, 'w') as f:
            f.write(self._generate_html_report(results, network_data, vulnerability_data, directory_data, web_vulnerability_data))
            
        self.logger.info(f"Informe final generado en {html_report}")
        return html_report
        
    def _generate_html_report(self, results, network_data, vulnerability_data, directory_data, web_vulnerability_data):
        """
        Genera el contenido HTML del informe final.
        
        Args:
            results (dict): Resultados del escaneo completo
            network_data (dict): Datos detallados del escaneo de red
            vulnerability_data (dict): Datos detallados del análisis de vulnerabilidades
            directory_data (list): Datos detallados del escaneo de directorios
            web_vulnerability_data (dict): Datos detallados del análisis de vulnerabilidades web
            
        Returns:
            str: Contenido HTML del informe
        """
        timestamp = results.get("timestamp", datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
        target = results.get("target", "Desconocido")
        web_url = results.get("web_url", "Desconocido")
        
        html = []
        html.append("<!DOCTYPE html>")
        html.append("<html lang='es'>")
        html.append("<head>")
        html.append("    <meta charset='UTF-8'>")
        html.append("    <meta name='viewport' content='width=device-width, initial-scale=1.0'>")
        html.append("    <title>Informe de Ciberseguridad</title>")
        html.append("    <style>")
        html.append("        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }")
        html.append("        h1, h2, h3 { color: #2c3e50; }")
        html.append("        .container { max-width: 1200px; margin: 0 auto; }")
        html.append("        .header { background-color: #34495e; color: white; padding: 20px; margin-bottom: 20px; }")
        html.append("        .summary { display: flex; justify-content: space-around; margin-bottom: 30px; }")
        html.append("        .summary-box { border: 1px solid #ddd; padding: 15px; border-radius: 5px; width: 22%; text-align: center; }")
        html.append("        .completed { background-color: #4caf50; color: white; }")
        html.append("        .failed { background-color: #f44336; color: white; }")
        html.append("        .skipped { background-color: #9e9e9e; color: white; }")
        html.append("        .section { margin-bottom: 30px; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }")
        html.append("        .vulnerability { background-color: #f9f9f9; padding: 15px; margin-bottom: 10px; border-radius: 5px; }")
        html.append("        .vulnerability.high { border-left: 4px solid #ff5252; }")
        html.append("        .vulnerability.medium { border-left: 4px solid #ff9800; }")
        html.append("        .vulnerability.low { border-left: 4px solid #4caf50; }")
        html.append("        table { width: 100%; border-collapse: collapse; }")
        html.append("        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }")
        html.append("        th { background-color: #f2f2f2; }")
        html.append("        .chart { width: 100%; max-width: 600px; margin: 0 auto; }")
        html.append("    </style>")
        html.append("</head>")
        html.append("<body>")
        html.append("    <div class='container'>")
        html.append("        <div class='header'>")
        html.append("            <h1>Informe de Análisis de Ciberseguridad</h1>")
        html.append(f"            <p>Fecha: {datetime.datetime.strptime(timestamp, '%Y%m%d_%H%M%S').strftime('%Y-%m-%d %H:%M:%S')}</p>")
        html.append(f"            <p>Objetivo: {target}</p>")
        html.append(f"            <p>URL Web: {web_url}</p>")
        html.append("        </div>")
        
        # Resumen
        html.append("        <h2>Resumen</h2>")
        html.append("        <div class='summary'>")
        html.append(f"            <div class='summary-box {results['network_scan'].get('status', 'failed')}'><h3>Escaneo de Red</h3><p>{results['network_scan'].get('hosts_found', 0)} hosts</p></div>")
        html.append(f"            <div class='summary-box {results['vulnerability_scan'].get('status', 'failed')}'><h3>Vulnerabilidades</h3><p>{results['vulnerability_scan'].get('vulnerabilities_found', 0)} encontradas</p></div>")
        html.append(f"            <div class='summary-box {results['directory_scan'].get('status', 'skipped')}'><h3>Directorios Web</h3><p>{results['directory_scan'].get('directories_found', 0)} encontrados</p></div>")
        html.append(f"            <div class='summary-box {results['web_vulnerability_scan'].get('status', 'skipped')}'><h3>Vulnerabilidades Web</h3><p>{results['web_vulnerability_scan'].get('vulnerabilities_found', 0)} encontradas</p></div>")
        html.append("        </div>")
        
        # Sección de escaneo de red
        html.append("        <div class='section'>")
        html.append("            <h2>Escaneo de Red</h2>")
        
        if results['network_scan'].get('status') == 'completed' and network_data:
            html.append("            <table>")
            html.append("                <tr>")
            html.append("                    <th>Host</th>")
            html.append("                    <th>Puertos Abiertos</th>")
            html.append("                    <th>Sistema Operativo</th>")
            html.append("                </tr>")
            
            for host_ip, host_data in network_data.items():
                ports_str = ", ".join([f"{p['port']}/{p.get('service', 'unknown')}" for p in host_data.get('ports', [])])
                os_info = host_data.get('os', {}).get('name', 'Desconocido')
                
                html.append("                <tr>")
                html.append(f"                    <td>{host_ip}</td>")
                html.append(f"                    <td>{ports_str}</td>")
                html.append(f"                    <td>{os_info}</td>")
                html.append("                </tr>")
                
            html.append("            </table>")
            
            # Añadir mapa de red si existe
            network_map = os.path.join(os.path.dirname(results['network_scan'].get('results_file', '')), f"network_map_{timestamp}.png")
            if os.path.exists(network_map):
                rel_path = os.path.basename(network_map)
                html.append(f"            <div class='chart'><img src='{rel_path}' alt='Mapa de red' width='100%'></div>")
                
        else:
            html.append("            <p>No se completó el escaneo de red o no se encontraron resultados.</p>")
            
        html.append("        </div>")
        
        # Sección de vulnerabilidades
        html.append("        <div class='section'>")
        html.append("            <h2>Análisis de Vulnerabilidades</h2>")
        
        if results['vulnerability_scan'].get('status') == 'completed' and vulnerability_data:
            # Contar vulnerabilidades por nivel de riesgo
            risk_counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
            
            for host_ip, vulns in vulnerability_data.items():
                for vuln in vulns:
                    risk_level = vuln.get('risk_level', 'Info')
                    if risk_level in risk_counts:
                        risk_counts[risk_level] += 1
                    else:
                        risk_counts["Info"] += 1
            
            # Mostrar resumen por nivel de riesgo
            html.append("            <div class='summary'>")
            html.append(f"                <div class='summary-box high'><h3>Alto</h3><p>{risk_counts['High']}</p></div>")
            html.append(f"                <div class='summary-box medium'><h3>Medio</h3><p>{risk_counts['Medium']}</p></div>")
            html.append(f"                <div class='summary-box low'><h3>Bajo</h3><p>{risk_counts['Low'] + risk_counts['Info']}</p></div>")
            html.append("            </div>")
            
            # Mostrar vulnerabilidades de alto riesgo
            high_risk_vulns = []
            for host_ip, vulns in vulnerability_data.items():
                for vuln in vulns:
                    if vuln.get('risk_level') == 'High':
                        high_risk_vulns.append((host_ip, vuln))
            
            if high_risk_vulns:
                html.append("            <h3>Vulnerabilidades de Alto Riesgo</h3>")
                
                for host_ip, vuln in high_risk_vulns:
                    html.append(f"            <div class='vulnerability high'>")
                    html.append(f"                <h4>{vuln.get('name', 'Vulnerabilidad desconocida')}</h4>")
                    html.append(f"                <p><strong>Host:</strong> {host_ip}</p>")
                    
                    if 'description' in vuln:
                        html.append(f"                <p><strong>Descripción:</strong> {vuln['description']}</p>")
                        
                    if 'solution' in vuln:
                        html.append(f"                <p><strong>Solución:</strong> {vuln['solution']}</p>")
                        
                    html.append("            </div>")
            else:
                html.append("            <p>No se encontraron vulnerabilidades de alto riesgo.</p>")
                
        else:
            html.append("            <p>No se completó el análisis de vulnerabilidades o no se encontraron resultados.</p>")
            
        html.append("        </div>")
        
        # Sección de directorios web
        html.append("        <div class='section'>")
        html.append("            <h2>Escaneo de Directorios Web</h2>")
        
        if results['directory_scan'].get('status') == 'completed' and directory_data:
            # Mostrar directorios interesantes
            interesting_dirs = [d for d in directory_data if d.get('interesting', False)]
            
            if interesting_dirs:
                html.append("            <h3>Directorios Interesantes</h3>")
                html.append("            <table>")
                html.append("                <tr>")
                html.append("                    <th>URL</th>")
                html.append("                    <th>Código</th>")
                html.append("                    <th>Tipo</th>")
                html.append("                    <th>Tamaño</th>")
                html.append("                </tr>")
                
                for dir_data in interesting_dirs:
                    html.append("                <tr>")
                    html.append(f"                    <td><a href='{dir_data.get('url', '#')}' target='_blank'>{dir_data.get('url', 'N/A')}</a></td>")
                    html.append(f"                    <td>{dir_data.get('status_code', 'N/A')}</td>")
                    html.append(f"                    <td>{dir_data.get('content_type', 'N/A')}</td>")
                    html.append(f"                    <td>{dir_data.get('content_length', 'N/A')}</td>")
                    html.append("                </tr>")
                    
                html.append("            </table>")
            else:
                html.append("            <p>No se encontraron directorios interesantes.</p>")
                
            # Mostrar resumen por código de estado
            status_counts = {}
            for dir_data in directory_data:
                status = dir_data.get('status_code', 0)
                if status not in status_counts:
                    status_counts[status] = 0
                status_counts[status] += 1
                
            html.append("            <h3>Distribución por Código de Estado</h3>")
            html.append("            <table>")
            html.append("                <tr>")
            html.append("                    <th>Código</th>")
            html.append("                    <th>Cantidad</th>")
            html.append("                </tr>")
            
            for status, count in sorted(status_counts.items()):
                html.append("                <tr>")
                html.append(f"                    <td>{status}</td>")
                html.append(f"                    <td>{count}</td>")
                html.append("                </tr>")
                
            html.append("            </table>")
            
        else:
            html.append("            <p>No se completó el escaneo de directorios web o no se encontraron resultados.</p>")
            
        html.append("        </div>")
        
        # Sección de vulnerabilidades web
        html.append("        <div class='section'>")
        html.append("            <h2>Análisis de Vulnerabilidades Web</h2>")
        
        if results['web_vulnerability_scan'].get('status') == 'completed' and web_vulnerability_data:
            # Contar vulnerabilidades por nivel de riesgo
            risk_counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
            
            for url, vulns in web_vulnerability_data.get('urls', {}).items():
                for vuln in vulns:
                    risk_level = vuln.get('risk_level', 'Info')
                    if risk_level in risk_counts:
                        risk_counts[risk_level] += 1
                    else:
                        risk_counts["Info"] += 1
            
            # Mostrar resumen por nivel de riesgo
            html.append("            <div class='summary'>")
            html.append(f"                <div class='summary-box high'><h3>Alto</h3><p>{risk_counts['High']}</p></div>")
            html.append(f"                <div class='summary-box medium'><h3>Medio</h3><p>{risk_counts['Medium']}</p></div>")
            html.append(f"                <div class='summary-box low'><h3>Bajo</h3><p>{risk_counts['Low'] + risk_counts['Info']}</p></div>")
            html.append("            </div>")
            
            # Mostrar vulnerabilidades de alto riesgo
            high_risk_vulns = []
            for url, vulns in web_vulnerability_data.get('urls', {}).items():
                for vuln in vulns:
                    if vuln.get('risk_level') == 'High':
                        high_risk_vulns.append((url, vuln))
            
            if high_risk_vulns:
                html.append("            <h3>Vulnerabilidades Web de Alto Riesgo</h3>")
                
                for url, vuln in high_risk_vulns:
                    html.append(f"            <div class='vulnerability high'>")
                    html.append(f"                <h4>{vuln.get('name', 'Vulnerabilidad desconocida')}</h4>")
                    html.append(f"                <p><strong>URL:</strong> <a href='{vuln.get('url', url)}' target='_blank'>{vuln.get('url', url)}</a></p>")
                    
                    if 'description' in vuln:
                        html.append(f"                <p><strong>Descripción:</strong> {vuln['description']}</p>")
                        
                    if 'parameter' in vuln and vuln['parameter']:
                        html.append(f"                <p><strong>Parámetro afectado:</strong> {vuln['parameter']}</p>")
                        
                    if 'solution' in vuln:
                        html.append(f"                <p><strong>Solución:</strong> {vuln['solution']}</p>")
                        
                    html.append("            </div>")
            else:
                html.append("            <p>No se encontraron vulnerabilidades web de alto riesgo.</p>")
                
        else:
            html.append("            <p>No se completó el análisis de vulnerabilidades web o no se encontraron resultados.</p>")
            
        html.append("        </div>")
        
        # Recomendaciones
        html.append("        <div class='section'>")
        html.append("            <h2>Recomendaciones</h2>")
        html.append("            <ol>")
        html.append("                <li>Priorizar la mitigación de vulnerabilidades de alto riesgo.</li>")
        html.append("                <li>Implementar un programa de gestión de parches para mantener los sistemas actualizados.</li>")
        html.append("                <li>Configurar correctamente los firewalls y sistemas de seguridad perimetral.</li>")
        html.append("                <li>Implementar validación y sanitización de entradas de usuario en aplicaciones web.</li>")
        html.append("                <li>Establecer políticas de contraseñas seguras y autenticación multifactor.</li>")
        html.append("                <li>Realizar escaneos de seguridad periódicos para detectar nuevas vulnerabilidades.</li>")
        html.append("                <li>Implementar cabeceras de seguridad HTTP adecuadas en aplicaciones web.</li>")
        html.append("                <li>Seguir el principio de defensa en profundidad en toda la infraestructura.</li>")
        html.append("            </ol>")
        html.append("        </div>")
        
        # Pie de página
        html.append("        <div style='margin-top: 50px; text-align: center; color: #777;'>")
        html.append("            <p>Informe generado automáticamente por la Herramienta de Ciberseguridad</p>")
        html.append("        </div>")
        
        html.append("    </div>")
        html.append("</body>")
        html.append("</html>")
        
        return "\n".join(html)

def main():
    # Configurar argumentos
    parser = argparse.ArgumentParser(description='Herramienta de Ciberseguridad')
    parser.add_argument('--target', required=True, help='Objetivo a escanear (IP, rango de IPs o dominio)')
    parser.add_argument('--web-url', help='URL del sitio web (si es diferente del target)')
    parser.add_argument('--scan-type', choices=['fast', 'normal', 'deep'], default='normal', help='Tipo de escaneo de red')
    parser.add_argument('--ports', help='Puertos a escanear (ej. "22,80,443" o "1-1000")')
    parser.add_argument('--wordlist', help='Nombre o ruta del diccionario para escaneo de directorios')
    parser.add_argument('--extensions', help='Lista de extensiones para escaneo de directorios, separadas por comas')
    parser.add_argument('--threads', type=int, default=10, help='Número de hilos para escaneo paralelo')
    parser.add_argument('--crawl-depth', type=int, default=1, help='Profundidad de rastreo para análisis de vulnerabilidades web')
    parser.add_argument('--max-urls', type=int, default=10, help='Número máximo de URLs a analizar')
    parser.add_argument('--scan-types', help='Tipos de escaneo de vulnerabilidades web, separados por comas')
    parser.add_argument('--output', default='./output', help='Directorio de salida')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO', help='Nivel de logging')
    args = parser.parse_args()
    
    # Configurar nivel de logging
    log_level = getattr(logging, args.log_level)
    
    # Inicializar herramienta
    tool = CibersecurityTool(output_dir=args.output, log_level=log_level)
    
    # Inicializar componentes
    if not tool.initialize_components():
        print("Error al inicializar componentes. Abortando.")
        return 1
    
    # Preparar extensiones si se proporcionan
    extensions = None
    if args.extensions:
        extensions = args.extensions.split(',')
    
    # Preparar tipos de escaneo si se proporcionan
    scan_types = None
    if args.scan_types:
        scan_types = args.scan_types.split(',')
    
    # Ejecutar escaneo completo
    results = tool.run_complete_scan(
        target=args.target,
        web_url=args.web_url,
        scan_type=args.scan_type,
        ports=args.ports,
        wordlist=args.wordlist,
        extensions=extensions,
        threads=args.threads,
        crawl_depth=args.crawl_depth,
        max_urls=args.max_urls,
        scan_types=scan_types
    )
    
    # Mostrar resumen de resultados
    print("\n=== RESUMEN DE RESULTADOS ===")
    print(f"Objetivo: {args.target}")
    print(f"Escaneo de red: {results['network_scan'].get('status')} - {results['network_scan'].get('hosts_found', 0)} hosts encontrados")
    print(f"Análisis de vulnerabilidades: {results['vulnerability_scan'].get('status')} - {results['vulnerability_scan'].get('vulnerabilities_found', 0)} vulnerabilidades encontradas")
    print(f"Escaneo de directorios web: {results['directory_scan'].get('status')} - {results['directory_scan'].get('directories_found', 0)} directorios encontrados")
    print(f"Análisis de vulnerabilidades web: {results['web_vulnerability_scan'].get('status')} - {results['web_vulnerability_scan'].get('vulnerabilities_found', 0)} vulnerabilidades encontradas")
    print(f"\nInforme completo guardado en: {os.path.join(os.path.dirname(results['network_scan'].get('results_file', '')), 'complete_scan_report.html')}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
