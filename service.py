"""
Clase Service para representar un servicio detectado en un puerto.

Esta clase almacena información sobre un servicio, incluyendo su nombre,
versión, producto y otra información relevante.
"""

class Service:
    def __init__(self, name="unknown", product=None, version=None):
        """
        Inicializa un nuevo objeto Service.
        
        Args:
            name (str, opcional): Nombre del servicio
            product (str, opcional): Producto específico
            version (str, opcional): Versión del servicio
        """
        self.name = name
        self.product = product
        self.version = version
        self.extra_info = {}
        
    def add_info(self, key, value):
        """
        Añade información adicional sobre el servicio.
        
        Args:
            key (str): Clave de la información
            value (str): Valor de la información
        """
        self.extra_info[key] = value
        
    def to_dict(self):
        """
        Convierte el objeto Service a un diccionario.
        
        Returns:
            dict: Representación del servicio como diccionario
        """
        return {
            'name': self.name,
            'product': self.product,
            'version': self.version,
            'extra_info': self.extra_info
        }
    
    def __str__(self):
        """
        Representación en cadena del servicio.
        
        Returns:
            str: Cadena que representa el servicio
        """
        version_str = f" {self.version}" if self.version else ""
        product_str = f" ({self.product})" if self.product else ""
        return f"{self.name}{product_str}{version_str}"
