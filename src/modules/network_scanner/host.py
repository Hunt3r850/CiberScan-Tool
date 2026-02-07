"""
Clase Host para representar un host descubierto en la red.

Esta clase almacena información sobre un host, incluyendo su dirección IP,
estado, puertos abiertos y servicios detectados.
"""

class Host:
    def __init__(self, ip_address, hostname=None, status="unknown"):
        """
        Inicializa un nuevo objeto Host.
        
        Args:
            ip_address (str): Dirección IP del host
            hostname (str, opcional): Nombre del host si está disponible
            status (str, opcional): Estado del host (up, down, unknown)
        """
        self.ip_address = ip_address
        self.hostname = hostname
        self.status = status
        self.ports = []
        self.os_info = {}
        self.last_scan_time = None
        
    def add_port(self, port):
        """
        Añade un puerto al host.
        
        Args:
            port (Port): Objeto Port que representa un puerto abierto
        """
        self.ports.append(port)
        
    def set_os_info(self, os_info):
        """
        Establece la información del sistema operativo.
        
        Args:
            os_info (dict): Diccionario con información del sistema operativo
        """
        self.os_info = os_info
        
    def to_dict(self):
        """
        Convierte el objeto Host a un diccionario.
        
        Returns:
            dict: Representación del host como diccionario
        """
        return {
            'ip_address': self.ip_address,
            'hostname': self.hostname,
            'status': self.status,
            'ports': [port.to_dict() for port in self.ports],
            'os_info': self.os_info,
            'last_scan_time': self.last_scan_time
        }
    
    def __str__(self):
        """
        Representación en cadena del host.
        
        Returns:
            str: Cadena que representa el host
        """
        hostname_str = f" ({self.hostname})" if self.hostname else ""
        return f"Host: {self.ip_address}{hostname_str} - Status: {self.status} - Ports: {len(self.ports)}"
