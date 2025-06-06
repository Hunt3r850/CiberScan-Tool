"""
Clase Port para representar un puerto descubierto en un host.

Esta clase almacena información sobre un puerto, incluyendo su número,
protocolo, estado y servicio asociado.
"""

class Port:
    def __init__(self, number, protocol="tcp", state="closed"):
        """
        Inicializa un nuevo objeto Port.
        
        Args:
            number (int): Número de puerto
            protocol (str, opcional): Protocolo (tcp, udp)
            state (str, opcional): Estado del puerto (open, closed, filtered)
        """
        self.number = number
        self.protocol = protocol
        self.state = state
        self.service = None
        
    def set_service(self, service):
        """
        Establece el servicio asociado al puerto.
        
        Args:
            service (Service): Objeto Service que representa el servicio detectado
        """
        self.service = service
        
    def to_dict(self):
        """
        Convierte el objeto Port a un diccionario.
        
        Returns:
            dict: Representación del puerto como diccionario
        """
        return {
            'number': self.number,
            'protocol': self.protocol,
            'state': self.state,
            'service': self.service.to_dict() if self.service else None
        }
    
    def __str__(self):
        """
        Representación en cadena del puerto.
        
        Returns:
            str: Cadena que representa el puerto
        """
        service_str = f" - {self.service}" if self.service else ""
        return f"{self.protocol}/{self.number} ({self.state}){service_str}"
