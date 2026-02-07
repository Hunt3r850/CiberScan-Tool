"""
Clases de integración con herramientas externas de análisis de vulnerabilidades web.

Este módulo proporciona clases para integrar herramientas externas como
Nikto y OWASP ZAP en el escáner de vulnerabilidades web.
"""

import os
import subprocess
import tempfile
import json
import logging
import time
import xml.etree.ElementTree as ET
from ..vulnerability import WebVulnerability

class NiktoScanner:
    def __init__(self, nikto_path=None, log_level=logging.INFO):
        """
        Inicializa un nuevo objeto NiktoScanner.
        
        Args:
            nikto_path (str, opcional): Ruta al ejecutable de Nikto
            log_level (int, opcional): Nivel de logging
        """
        self.nikto_path = nikto_path or "nikto"
        self.logger = self._setup_logger(log_level)
        
    def _setup_logger(self, log_level):
        """
        Configura el logger para el escáner.
        
        Args:
            log_level (int): Nivel de logging
            
        Returns:
            Logger: Objeto logger configurado
        """
        logger = logging.getLogger("NiktoScanner")
        logger.setLevel(log_level)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger
        
    def check_installation(self):
        """
        Verifica si Nikto está instalado y disponible.
        
        Returns:
            bool: True si Nikto está disponible, False en caso contrario
        """
        try:
            process = subprocess.run([self.nikto_path, "-Version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return process.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            self.logger.error("Nikto no está instalado o no está en el PATH")
            return False
            
    def scan_url(self, url, options=None):
        """
        Escanea una URL utilizando Nikto.
        
        Args:
            url (str): URL a escanear
            options (dict, opcional): Opciones adicionales para Nikto
            
        Returns:
            list: Lista de objetos WebVulnerability encontrados
        """
        self.logger.info(f"Escaneando {url} con Nikto")
        
        # Verificar instalación
        if not self.check_installation():
            self.logger.error("No se puede realizar el escaneo con Nikto")
            return []
            
        # Crear archivo temporal para la salida
        fd, output_file = tempfile.mkstemp(suffix='.xml')
        os.close(fd)
        
        # Preparar comando
        cmd = [self.nikto_path, "-h", url, "-o", output_file, "-Format", "xml"]
        
        # Añadir opciones adicionales
        if options:
            for key, value in options.items():
                if key.startswith("-"):
                    cmd.append(key)
                    if value:
                        cmd.append(str(value))
                else:
                    cmd.append(f"-{key}")
                    if value:
                        cmd.append(str(value))
        
        # Ejecutar Nikto
        try:
            self.logger.debug(f"Ejecutando comando: {' '.join(cmd)}")
            process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            if process.returncode != 0:
                self.logger.error(f"Error al ejecutar Nikto: {process.stderr.decode('utf-8', errors='ignore')}")
                return []
                
            # Parsear resultados
            vulnerabilities = self._parse_nikto_xml(output_file, url)
            self.logger.info(f"Escaneo con Nikto completado. Encontradas {len(vulnerabilities)} vulnerabilidades")
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error durante el escaneo con Nikto: {str(e)}")
            return []
            
        finally:
            # Limpiar archivo temporal
            if os.path.exists(output_file):
                os.remove(output_file)
                
    def _parse_nikto_xml(self, xml_file, url):
        """
        Parsea el archivo XML de salida de Nikto.
        
        Args:
            xml_file (str): Ruta al archivo XML
            url (str): URL escaneada
            
        Returns:
            list: Lista de objetos WebVulnerability
        """
        vulnerabilities = []
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Buscar elementos de vulnerabilidad
            for item in root.findall(".//item"):
                try:
                    # Extraer información
                    description = item.find("description").text if item.find("description") is not None else "Sin descripción"
                    osvdb_id = item.find("osvdbid").text if item.find("osvdbid") is not None else None
                    method = item.find("method").text if item.find("method") is not None else "GET"
                    uri = item.find("uri").text if item.find("uri") is not None else "/"
                    
                    # Determinar nivel de riesgo basado en el ID de OSVDB
                    risk_level = "Medium"  # Por defecto
                    if osvdb_id:
                        # Algunos IDs conocidos de alto riesgo
                        high_risk_ids = ["3268", "877", "5646", "12184", "3092", "732"]
                        if osvdb_id in high_risk_ids:
                            risk_level = "High"
                    
                    # Crear objeto de vulnerabilidad
                    vuln = WebVulnerability(
                        name=f"Nikto: {description[:50]}..." if len(description) > 50 else f"Nikto: {description}",
                        description=description,
                        risk_level=risk_level,
                        confidence="Medium"
                    )
                    
                    vuln.set_url(f"{url}{uri}")
                    if osvdb_id:
                        vuln.add_reference(f"OSVDB-{osvdb_id}")
                    vuln.set_tool("Nikto")
                    
                    vulnerabilities.append(vuln)
                    
                except Exception as e:
                    self.logger.error(f"Error al procesar elemento de vulnerabilidad: {str(e)}")
                    continue
                    
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error al parsear archivo XML de Nikto: {str(e)}")
            return []

class ZapScanner:
    def __init__(self, zap_path=None, api_key=None, port=8080, log_level=logging.INFO):
        """
        Inicializa un nuevo objeto ZapScanner.
        
        Args:
            zap_path (str, opcional): Ruta al ejecutable de ZAP
            api_key (str, opcional): Clave API para ZAP
            port (int, opcional): Puerto para la API de ZAP
            log_level (int, opcional): Nivel de logging
        """
        self.zap_path = zap_path
        self.api_key = api_key
        self.port = port
        self.logger = self._setup_logger(log_level)
        self.zap_process = None
        self.zap_api = None
        
    def _setup_logger(self, log_level):
        """
        Configura el logger para el escáner.
        
        Args:
            log_level (int): Nivel de logging
            
        Returns:
            Logger: Objeto logger configurado
        """
        logger = logging.getLogger("ZapScanner")
        logger.setLevel(log_level)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger
        
    def start_zap(self):
        """
        Inicia el proceso de ZAP.
        
        Returns:
            bool: True si ZAP se inició correctamente, False en caso contrario
        """
        if self.zap_process:
            self.logger.info("ZAP ya está en ejecución")
            return True
            
        try:
            # Intentar importar la API de Python de ZAP
            try:
                from zapv2 import ZAPv2
            except ImportError:
                self.logger.error("No se pudo importar la API de Python de ZAP. Instálala con 'pip install python-owasp-zap-v2.4'")
                return False
                
            # Si se proporciona una ruta a ZAP, iniciar el proceso
            if self.zap_path:
                cmd = [self.zap_path, "-daemon", "-port", str(self.port)]
                if self.api_key:
                    cmd.extend(["-config", f"api.key={self.api_key}"])
                    
                self.logger.info(f"Iniciando ZAP: {' '.join(cmd)}")
                self.zap_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Esperar a que ZAP esté listo
                time.sleep(10)
            
            # Conectar a la API de ZAP
            zap_options = {
                'apikey': self.api_key,
                'proxies': {'http': f'http://localhost:{self.port}', 'https': f'http://localhost:{self.port}'}
            }
            self.zap_api = ZAPv2(**zap_options)
            
            # Verificar conexión
            version = self.zap_api.core.version
            self.logger.info(f"Conectado a ZAP {version}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error al iniciar ZAP: {str(e)}")
            return False
            
    def stop_zap(self):
        """
        Detiene el proceso de ZAP.
        
        Returns:
            bool: True si ZAP se detuvo correctamente, False en caso contrario
        """
        if not self.zap_process:
            return True
            
        try:
            # Intentar detener ZAP a través de la API
            if self.zap_api:
                self.zap_api.core.shutdown()
                time.sleep(2)
                
            # Verificar si el proceso aún está en ejecución
            if self.zap_process.poll() is None:
                self.zap_process.terminate()
                self.zap_process.wait(timeout=10)
                
            self.zap_process = None
            self.zap_api = None
            self.logger.info("ZAP detenido correctamente")
            return True
            
        except Exception as e:
            self.logger.error(f"Error al detener ZAP: {str(e)}")
            return False
            
    def scan_url(self, url, options=None):
        """
        Escanea una URL utilizando OWASP ZAP.
        
        Args:
            url (str): URL a escanear
            options (dict, opcional): Opciones adicionales para ZAP
            
        Returns:
            list: Lista de objetos WebVulnerability encontrados
        """
        self.logger.info(f"Escaneando {url} con OWASP ZAP")
        
        # Iniciar ZAP si es necesario
        if not self.zap_api and not self.start_zap():
            self.logger.error("No se puede realizar el escaneo con ZAP")
            return []
            
        vulnerabilities = []
        
        try:
            # Configurar opciones
            scan_options = {
                'recurse': True,
                'inScopeOnly': False,
                'scanPolicyName': None,
                'method': None,
                'postData': None
            }
            
            if options:
                scan_options.update(options)
                
            # Acceder a la URL
            self.logger.info(f"Accediendo a {url}")
            self.zap_api.urlopen(url)
            time.sleep(2)
            
            # Escaneo pasivo
            self.logger.info("Realizando escaneo pasivo")
            self.zap_api.pscan.enable_all_scanners()
            
            # Escaneo activo
            self.logger.info("Iniciando escaneo activo")
            scan_id = self.zap_api.ascan.scan(url, **scan_options)
            
            # Esperar a que termine el escaneo
            while int(self.zap_api.ascan.status(scan_id)) < 100:
                self.logger.info(f"Progreso del escaneo: {self.zap_api.ascan.status(scan_id)}%")
                time.sleep(5)
                
            self.logger.info("Escaneo activo completado")
            
            # Obtener alertas
            alerts = self.zap_api.core.alerts(url)
            
            # Procesar alertas
            for alert in alerts:
                risk_level_map = {
                    "3": "High",
                    "2": "Medium",
                    "1": "Low",
                    "0": "Info"
                }
                
                confidence_map = {
                    "3": "High",
                    "2": "Medium",
                    "1": "Low",
                    "0": "Info"
                }
                
                risk_level = risk_level_map.get(str(alert.get('risk')), "Info")
                confidence = confidence_map.get(str(alert.get('confidence')), "Low")
                
                vuln = WebVulnerability(
                    name=alert.get('name', 'Unknown'),
                    description=alert.get('description', ''),
                    risk_level=risk_level,
                    confidence=confidence
                )
                
                vuln.set_url(alert.get('url', url))
                vuln.set_parameter(alert.get('param', ''))
                vuln.set_evidence(alert.get('evidence', ''))
                vuln.set_solution(alert.get('solution', ''))
                
                if 'reference' in alert:
                    for ref in alert['reference'].split('\n'):
                        if ref.strip():
                            vuln.add_reference(ref.strip())
                            
                if 'cweid' in alert:
                    vuln.set_cwe_id(f"CWE-{alert['cweid']}")
                    
                vuln.set_tool("OWASP ZAP")
                
                vulnerabilities.append(vuln)
                
            self.logger.info(f"Escaneo con ZAP completado. Encontradas {len(vulnerabilities)} vulnerabilidades")
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error durante el escaneo con ZAP: {str(e)}")
            return []
            
        finally:
            # No detenemos ZAP aquí para permitir múltiples escaneos
            pass
