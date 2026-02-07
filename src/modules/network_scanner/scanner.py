"""
Clase NetworkScanner para realizar escaneos de red utilizando Nmap y Masscan.

Esta clase proporciona métodos para descubrir hosts, escanear puertos y
detectar servicios en una red utilizando diferentes herramientas.
"""

import nmap
import subprocess
import json
import os
import datetime
import logging
import tempfile
from src.modules.network_scanner.host import Host
from src.modules.network_scanner.port import Port
from src.modules.network_scanner.service import Service

class NetworkScanner:
    def __init__(self, log_level=logging.INFO):
        """
        Inicializa un nuevo objeto NetworkScanner.
        
        Args:
            log_level (int, opcional): Nivel de logging
        """
        self.nm = nmap.PortScanner()
        self.logger = self._setup_logger(log_level)
        
    def _setup_logger(self, log_level):
        """
        Configura el logger para el escáner.
        
        Args:
            log_level (int): Nivel de logging
            
        Returns:
            Logger: Objeto logger configurado
        """
        logger = logging.getLogger("NetworkScanner")
        logger.setLevel(log_level)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger
        
    def discover_hosts(self, target, method="ping"):
        """
        Descubre hosts activos en la red.
        
        Args:
            target (str): Objetivo del escaneo (IP, rango, subred)
            method (str, opcional): Método de descubrimiento ('ping', 'arp', 'syn')
            
        Returns:
            list: Lista de objetos Host descubiertos
        """
        self.logger.info(f"Descubriendo hosts en {target} usando método {method}")
        
        if method == "ping":
            args = "-sn"  # Ping scan
        elif method == "arp":
            args = "-PR"  # ARP scan
        elif method == "syn":
            args = "-PS"  # SYN scan
        else:
            args = "-sn"  # Default to ping scan
            
        try:
            self.nm.scan(hosts=target, arguments=args)
            hosts = []
            
            for host_ip in self.nm.all_hosts():
                host_status = self.nm[host_ip].state()
                hostname = self.nm[host_ip].hostname() if 'hostname' in self.nm[host_ip] else None
                
                host = Host(host_ip, hostname, host_status)
                host.last_scan_time = datetime.datetime.now()
                hosts.append(host)
                
            self.logger.info(f"Descubiertos {len(hosts)} hosts")
            return hosts
            
        except Exception as e:
            self.logger.error(f"Error al descubrir hosts: {str(e)}")
            return []
            
    def scan_ports(self, target, ports="1-1000", scan_type="basic"):
        """
        Escanea puertos en un host o rango de hosts.
        
        Args:
            target (str): Objetivo del escaneo (IP, rango, subred)
            ports (str, opcional): Puertos a escanear
            scan_type (str, opcional): Tipo de escaneo ('basic', 'comprehensive', 'stealth')
            
        Returns:
            list: Lista de objetos Host con información de puertos
        """
        self.logger.info(f"Escaneando puertos {ports} en {target} (tipo: {scan_type})")
        
        if scan_type == "basic":
            args = f"-sV -p {ports}"
        elif scan_type == "comprehensive":
            args = f"-sS -sV -sC -O -p {ports}"
        elif scan_type == "stealth":
            args = f"-sS -T2 -p {ports}"
        else:
            args = f"-sV -p {ports}"
            
        try:
            self.nm.scan(hosts=target, arguments=args)
            hosts = []
            
            for host_ip in self.nm.all_hosts():
                host_status = self.nm[host_ip].state()
                hostname = self.nm[host_ip].hostname() if 'hostname' in self.nm[host_ip] else None
                
                host = Host(host_ip, hostname, host_status)
                host.last_scan_time = datetime.datetime.now()
                
                if 'tcp' in self.nm[host_ip]:
                    for port_num, port_info in self.nm[host_ip]['tcp'].items():
                        port = Port(port_num, "tcp", port_info['state'])
                        
                        if 'name' in port_info:
                            service = Service(
                                port_info['name'],
                                port_info.get('product', None),
                                port_info.get('version', None)
                            )
                            
                            # Añadir información extra si está disponible
                            for key in ['extrainfo', 'cpe']:
                                if key in port_info and port_info[key]:
                                    service.add_info(key, port_info[key])
                                    
                            port.set_service(service)
                            
                        host.add_port(port)
                
                # Añadir información del sistema operativo si está disponible
                if 'osmatch' in self.nm[host_ip]:
                    os_matches = self.nm[host_ip]['osmatch']
                    if os_matches:
                        host.set_os_info({
                            'name': os_matches[0].get('name', 'Unknown'),
                            'accuracy': os_matches[0].get('accuracy', '0'),
                            'osclass': os_matches[0].get('osclass', [])
                        })
                
                hosts.append(host)
                
            self.logger.info(f"Escaneados {len(hosts)} hosts")
            return hosts
            
        except Exception as e:
            self.logger.error(f"Error al escanear puertos: {str(e)}")
            return []
            
    def masscan_scan(self, target, ports="0-65535", rate="1000"):
        """
        Realiza un escaneo rápido utilizando Masscan.
        
        Args:
            target (str): Objetivo del escaneo (IP, rango, subred)
            ports (str, opcional): Puertos a escanear
            rate (str, opcional): Tasa de paquetes por segundo
            
        Returns:
            list: Lista de objetos Host con información de puertos
        """
        self.logger.info(f"Ejecutando Masscan en {target} (puertos: {ports}, rate: {rate})")
        
        # Crear archivo temporal para la salida
        fd, output_file = tempfile.mkstemp(suffix='.json')
        os.close(fd)
        
        try:
            # Ejecutar masscan
            cmd = f"masscan {target} -p {ports} --rate={rate} -oJ {output_file}"
            subprocess.run(cmd, shell=True, check=True)
            
            # Leer y parsear los resultados
            with open(output_file, 'r') as f:
                content = f.read().strip()
                if not content:
                    self.logger.warning("Masscan no produjo resultados")
                    return []
                
                # Masscan puede no producir JSON válido si no hay resultados
                if content.startswith('[') and content.endswith(']'):
                    results = json.loads(content)
                else:
                    self.logger.warning("Formato de salida de Masscan no reconocido")
                    return []
            
            # Procesar resultados
            hosts_dict = {}
            for result in results:
                ip = result.get('ip', None)
                if not ip:
                    continue
                
                if ip not in hosts_dict:
                    hosts_dict[ip] = Host(ip, status="up")
                    hosts_dict[ip].last_scan_time = datetime.datetime.now()
                
                port_num = result.get('ports', [{}])[0].get('port', 0)
                if port_num:
                    port = Port(port_num, "tcp", "open")
                    hosts_dict[ip].add_port(port)
            
            hosts = list(hosts_dict.values())
            self.logger.info(f"Masscan descubrió {len(hosts)} hosts con puertos abiertos")
            return hosts
            
        except Exception as e:
            self.logger.error(f"Error al ejecutar Masscan: {str(e)}")
            return []
        finally:
            # Limpiar archivo temporal
            if os.path.exists(output_file):
                os.remove(output_file)
                
    def enrich_masscan_results(self, hosts):
        """
        Enriquece los resultados de Masscan con información de servicios usando Nmap.
        
        Args:
            hosts (list): Lista de objetos Host de Masscan
            
        Returns:
            list: Lista de objetos Host enriquecidos
        """
        self.logger.info(f"Enriqueciendo resultados de Masscan para {len(hosts)} hosts")
        
        enriched_hosts = []
        for host in hosts:
            if not host.ports:
                enriched_hosts.append(host)
                continue
                
            # Obtener lista de puertos para escanear con Nmap
            port_list = ",".join([str(port.number) for port in host.ports])
            
            try:
                # Usar Nmap para obtener información de servicios
                self.nm.scan(hosts=host.ip_address, arguments=f"-sV -p {port_list}")
                
                if host.ip_address in self.nm.all_hosts():
                    nmap_host = self.nm[host.ip_address]
                    
                    # Actualizar hostname si está disponible
                    if 'hostname' in nmap_host and nmap_host.hostname():
                        host.hostname = nmap_host.hostname()
                    
                    # Actualizar información de puertos
                    if 'tcp' in nmap_host:
                        for port in host.ports:
                            if port.number in nmap_host['tcp']:
                                port_info = nmap_host['tcp'][port.number]
                                
                                if 'name' in port_info:
                                    service = Service(
                                        port_info['name'],
                                        port_info.get('product', None),
                                        port_info.get('version', None)
                                    )
                                    
                                    # Añadir información extra si está disponible
                                    for key in ['extrainfo', 'cpe']:
                                        if key in port_info and port_info[key]:
                                            service.add_info(key, port_info[key])
                                            
                                    port.set_service(service)
                    
                    # Añadir información del sistema operativo si está disponible
                    if 'osmatch' in nmap_host:
                        os_matches = nmap_host['osmatch']
                        if os_matches:
                            host.set_os_info({
                                'name': os_matches[0].get('name', 'Unknown'),
                                'accuracy': os_matches[0].get('accuracy', '0'),
                                'osclass': os_matches[0].get('osclass', [])
                            })
                
            except Exception as e:
                self.logger.error(f"Error al enriquecer host {host.ip_address}: {str(e)}")
                
            enriched_hosts.append(host)
            
        self.logger.info(f"Enriquecimiento completado para {len(enriched_hosts)} hosts")
        return enriched_hosts
        
    def scan_network(self, target, scan_mode="normal"):
        """
        Realiza un escaneo completo de la red combinando diferentes técnicas.
        
        Args:
            target (str): Objetivo del escaneo (IP, rango, subred)
            scan_mode (str, opcional): Modo de escaneo ('fast', 'normal', 'comprehensive')
            
        Returns:
            list: Lista de objetos Host con información completa
        """
        self.logger.info(f"Iniciando escaneo de red en {target} (modo: {scan_mode})")
        
        if scan_mode == "fast":
            # Modo rápido: usar Masscan para descubrimiento inicial
            hosts = self.masscan_scan(target, ports="1-1024", rate="10000")
            # Enriquecer solo los primeros 10 hosts para evitar sobrecarga
            hosts_to_enrich = hosts[:10] if len(hosts) > 10 else hosts
            enriched_hosts = self.enrich_masscan_results(hosts_to_enrich)
            return enriched_hosts
            
        elif scan_mode == "comprehensive":
            # Modo exhaustivo: descubrir hosts y luego hacer escaneo completo
            hosts = self.discover_hosts(target)
            results = []
            
            for host in hosts:
                if host.status == "up":
                    # Escaneo completo para cada host activo
                    scanned_hosts = self.scan_ports(host.ip_address, ports="1-65535", scan_type="comprehensive")
                    if scanned_hosts:
                        results.append(scanned_hosts[0])
                    else:
                        results.append(host)
                else:
                    results.append(host)
                    
            return results
            
        else:  # Modo normal (predeterminado)
            # Descubrir hosts y escanear puertos comunes
            hosts = self.discover_hosts(target)
            results = []
            
            for host in hosts:
                if host.status == "up":
                    # Escaneo básico para cada host activo
                    scanned_hosts = self.scan_ports(host.ip_address, ports="1-1000", scan_type="basic")
                    if scanned_hosts:
                        results.append(scanned_hosts[0])
                    else:
                        results.append(host)
                else:
                    results.append(host)
                    
            return results
            
    def save_results(self, hosts, output_file):
        """
        Guarda los resultados del escaneo en un archivo JSON.
        
        Args:
            hosts (list): Lista de objetos Host
            output_file (str): Ruta del archivo de salida
            
        Returns:
            bool: True si se guardó correctamente, False en caso contrario
        """
        try:
            results = [host.to_dict() for host in hosts]
            
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=4, default=str)
                
            self.logger.info(f"Resultados guardados en {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error al guardar resultados: {str(e)}")
            return False
            
    def load_results(self, input_file):
        """
        Carga resultados de un archivo JSON previo.
        
        Args:
            input_file (str): Ruta del archivo de entrada
            
        Returns:
            list: Lista de objetos Host
        """
        try:
            with open(input_file, 'r') as f:
                data = json.load(f)
                
            hosts = []
            for host_data in data:
                host = Host(
                    host_data['ip_address'],
                    host_data.get('hostname'),
                    host_data.get('status', 'unknown')
                )
                
                # Cargar puertos
                for port_data in host_data.get('ports', []):
                    port = Port(
                        port_data['number'],
                        port_data.get('protocol', 'tcp'),
                        port_data.get('state', 'unknown')
                    )
                    
                    # Cargar servicio si existe
                    if port_data.get('service'):
                        service_data = port_data['service']
                        service = Service(
                            service_data.get('name', 'unknown'),
                            service_data.get('product'),
                            service_data.get('version')
                        )
                        
                        # Cargar información extra
                        for key, value in service_data.get('extra_info', {}).items():
                            service.add_info(key, value)
                            
                        port.set_service(service)
                        
                    host.add_port(port)
                
                # Cargar información del sistema operativo
                if 'os_info' in host_data:
                    host.set_os_info(host_data['os_info'])
                    
                # Cargar tiempo de escaneo
                if 'last_scan_time' in host_data:
                    try:
                        host.last_scan_time = datetime.datetime.fromisoformat(host_data['last_scan_time'])
                    except:
                        host.last_scan_time = None
                        
                hosts.append(host)
                
            self.logger.info(f"Cargados {len(hosts)} hosts desde {input_file}")
            return hosts
            
        except Exception as e:
            self.logger.error(f"Error al cargar resultados: {str(e)}")
            return []
