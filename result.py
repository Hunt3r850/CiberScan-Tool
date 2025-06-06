"""
Clase ScanResult para representar el resultado de un escaneo de directorios web.

Esta clase almacena información sobre un recurso web descubierto,
incluyendo su URL, código de estado, tamaño de respuesta y otros metadatos.
"""

import datetime

class ScanResult:
    def __init__(self, url, status_code, content_type=None, content_length=None, response_time=None):
        """
        Inicializa un nuevo objeto ScanResult.
        
        Args:
            url (str): URL completa del recurso descubierto
            status_code (int): Código de estado HTTP de la respuesta
            content_type (str, opcional): Tipo de contenido de la respuesta
            content_length (int, opcional): Tamaño de la respuesta en bytes
            response_time (float, opcional): Tiempo de respuesta en segundos
        """
        self.url = url
        self.status_code = status_code
        self.content_type = content_type
        self.content_length = content_length
        self.response_time = response_time
        self.discovery_time = datetime.datetime.now()
        self.notes = []
        self.interesting = False
        
    def add_note(self, note):
        """
        Añade una nota al resultado.
        
        Args:
            note (str): Nota o comentario sobre el resultado
        """
        self.notes.append(note)
        
    def mark_interesting(self, reason=None):
        """
        Marca el resultado como interesante.
        
        Args:
            reason (str, opcional): Razón por la que el resultado es interesante
        """
        self.interesting = True
        if reason:
            self.add_note(f"Marcado como interesante: {reason}")
            
    def is_success(self):
        """
        Verifica si el código de estado indica éxito.
        
        Returns:
            bool: True si el código de estado está en el rango 200-299
        """
        return 200 <= self.status_code < 300
        
    def is_redirect(self):
        """
        Verifica si el código de estado indica redirección.
        
        Returns:
            bool: True si el código de estado está en el rango 300-399
        """
        return 300 <= self.status_code < 400
        
    def is_client_error(self):
        """
        Verifica si el código de estado indica error del cliente.
        
        Returns:
            bool: True si el código de estado está en el rango 400-499
        """
        return 400 <= self.status_code < 500
        
    def is_server_error(self):
        """
        Verifica si el código de estado indica error del servidor.
        
        Returns:
            bool: True si el código de estado está en el rango 500-599
        """
        return 500 <= self.status_code < 600
        
    def to_dict(self):
        """
        Convierte el objeto ScanResult a un diccionario.
        
        Returns:
            dict: Representación del resultado como diccionario
        """
        return {
            'url': self.url,
            'status_code': self.status_code,
            'content_type': self.content_type,
            'content_length': self.content_length,
            'response_time': self.response_time,
            'discovery_time': self.discovery_time.isoformat(),
            'notes': self.notes,
            'interesting': self.interesting
        }
    
    def __str__(self):
        """
        Representación en cadena del resultado.
        
        Returns:
            str: Cadena que representa el resultado
        """
        status_indicator = "+" if self.is_success() else "-"
        interesting_indicator = "!" if self.interesting else " "
        size_str = f"{self.content_length} bytes" if self.content_length is not None else "unknown size"
        return f"[{status_indicator}][{interesting_indicator}] {self.status_code} - {self.url} ({size_str})"
