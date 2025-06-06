"""
Clase WordlistManager para gestionar diccionarios de palabras.

Esta clase proporciona métodos para cargar, filtrar y gestionar
diccionarios de palabras utilizados en los escaneos de directorios web.
"""

import os
import logging
import re

class WordlistManager:
    def __init__(self, wordlists_dir=None, log_level=logging.INFO):
        """
        Inicializa un nuevo objeto WordlistManager.
        
        Args:
            wordlists_dir (str, opcional): Directorio donde se encuentran los diccionarios
            log_level (int, opcional): Nivel de logging
        """
        if wordlists_dir is None:
            # Usar una ubicación predeterminada si no se especifica
            wordlists_dir = os.path.join(os.path.dirname(__file__), '../../../data/wordlists')
            
        self.wordlists_dir = wordlists_dir
        self.logger = self._setup_logger(log_level)
        self.available_wordlists = {}
        self._discover_wordlists()
        
    def _setup_logger(self, log_level):
        """
        Configura el logger para el gestor de diccionarios.
        
        Args:
            log_level (int): Nivel de logging
            
        Returns:
            Logger: Objeto logger configurado
        """
        logger = logging.getLogger("WordlistManager")
        logger.setLevel(log_level)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger
        
    def _discover_wordlists(self):
        """
        Descubre los diccionarios disponibles en el directorio configurado.
        """
        self.available_wordlists = {}
        
        # Crear directorio si no existe
        if not os.path.exists(self.wordlists_dir):
            os.makedirs(self.wordlists_dir)
            self.logger.info(f"Directorio de diccionarios creado: {self.wordlists_dir}")
            return
            
        # Buscar archivos de diccionario
        for filename in os.listdir(self.wordlists_dir):
            if filename.endswith('.txt') or filename.endswith('.dict'):
                filepath = os.path.join(self.wordlists_dir, filename)
                if os.path.isfile(filepath):
                    # Contar líneas para tener una idea del tamaño
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            line_count = sum(1 for _ in f)
                        
                        self.available_wordlists[filename] = {
                            'path': filepath,
                            'size': os.path.getsize(filepath),
                            'lines': line_count
                        }
                    except Exception as e:
                        self.logger.warning(f"Error al procesar diccionario {filename}: {str(e)}")
        
        self.logger.info(f"Descubiertos {len(self.available_wordlists)} diccionarios")
        
    def get_available_wordlists(self):
        """
        Obtiene la lista de diccionarios disponibles.
        
        Returns:
            dict: Diccionario con información sobre los diccionarios disponibles
        """
        return self.available_wordlists
        
    def load_wordlist(self, wordlist_name):
        """
        Carga un diccionario en memoria.
        
        Args:
            wordlist_name (str): Nombre del diccionario a cargar
            
        Returns:
            list: Lista de palabras del diccionario o None si hay error
        """
        if wordlist_name not in self.available_wordlists:
            # Comprobar si es una ruta absoluta
            if os.path.isfile(wordlist_name):
                filepath = wordlist_name
            else:
                self.logger.error(f"Diccionario no encontrado: {wordlist_name}")
                return None
        else:
            filepath = self.available_wordlists[wordlist_name]['path']
            
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
            self.logger.info(f"Diccionario {wordlist_name} cargado con {len(words)} palabras")
            return words
            
        except Exception as e:
            self.logger.error(f"Error al cargar diccionario {wordlist_name}: {str(e)}")
            return None
            
    def filter_wordlist(self, words, min_length=None, max_length=None, pattern=None):
        """
        Filtra un diccionario según criterios específicos.
        
        Args:
            words (list): Lista de palabras a filtrar
            min_length (int, opcional): Longitud mínima de las palabras
            max_length (int, opcional): Longitud máxima de las palabras
            pattern (str, opcional): Patrón regex que deben cumplir las palabras
            
        Returns:
            list: Lista de palabras filtradas
        """
        filtered_words = words
        
        # Filtrar por longitud mínima
        if min_length is not None:
            filtered_words = [w for w in filtered_words if len(w) >= min_length]
            
        # Filtrar por longitud máxima
        if max_length is not None:
            filtered_words = [w for w in filtered_words if len(w) <= max_length]
            
        # Filtrar por patrón
        if pattern is not None:
            try:
                regex = re.compile(pattern)
                filtered_words = [w for w in filtered_words if regex.search(w)]
            except re.error:
                self.logger.error(f"Patrón regex inválido: {pattern}")
                
        self.logger.info(f"Filtrado completado: {len(filtered_words)} palabras resultantes")
        return filtered_words
        
    def combine_wordlists(self, wordlists):
        """
        Combina múltiples diccionarios en uno solo.
        
        Args:
            wordlists (list): Lista de nombres de diccionarios a combinar
            
        Returns:
            list: Lista combinada de palabras sin duplicados
        """
        combined = set()
        
        for wordlist in wordlists:
            words = self.load_wordlist(wordlist)
            if words:
                combined.update(words)
                
        result = list(combined)
        self.logger.info(f"Combinación completada: {len(result)} palabras únicas")
        return result
        
    def save_wordlist(self, words, filename):
        """
        Guarda una lista de palabras como un nuevo diccionario.
        
        Args:
            words (list): Lista de palabras a guardar
            filename (str): Nombre del archivo de salida
            
        Returns:
            bool: True si se guardó correctamente, False en caso contrario
        """
        # Asegurar que el nombre de archivo termina en .txt
        if not filename.endswith('.txt'):
            filename += '.txt'
            
        filepath = os.path.join(self.wordlists_dir, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                for word in words:
                    f.write(f"{word}\n")
                    
            self.logger.info(f"Diccionario guardado en {filepath} con {len(words)} palabras")
            
            # Actualizar la lista de diccionarios disponibles
            self._discover_wordlists()
            return True
            
        except Exception as e:
            self.logger.error(f"Error al guardar diccionario {filename}: {str(e)}")
            return False
            
    def generate_extensions_list(self, web_type="common"):
        """
        Genera una lista de extensiones comunes según el tipo de aplicación web.
        
        Args:
            web_type (str): Tipo de aplicación web ('common', 'php', 'asp', 'java')
            
        Returns:
            list: Lista de extensiones
        """
        extensions = {
            "common": ["html", "htm", "php", "asp", "aspx", "jsp", "js", "txt", "pdf", "xml"],
            "php": ["php", "php3", "php4", "php5", "phtml", "inc"],
            "asp": ["asp", "aspx", "ashx", "asmx", "axd", "config"],
            "java": ["jsp", "jsf", "do", "action", "java", "class", "jar"],
            "backup": ["bak", "old", "backup", "~", "copy", "orig", "tmp", "temp"]
        }
        
        if web_type in extensions:
            return extensions[web_type]
        else:
            return extensions["common"]
            
    def add_common_prefixes_suffixes(self, words):
        """
        Añade prefijos y sufijos comunes a las palabras.
        
        Args:
            words (list): Lista de palabras base
            
        Returns:
            list: Lista ampliada con prefijos y sufijos
        """
        prefixes = ["admin_", "dev_", "test_", "old_", "new_", "backup_"]
        suffixes = ["_admin", "_dev", "_test", "_old", "_new", "_backup", "_1", "_2"]
        
        result = set(words)
        
        # Añadir prefijos
        for prefix in prefixes:
            for word in words:
                result.add(f"{prefix}{word}")
                
        # Añadir sufijos
        for suffix in suffixes:
            for word in words:
                result.add(f"{word}{suffix}")
                
        self.logger.info(f"Añadidos prefijos y sufijos: {len(result)} palabras resultantes")
        return list(result)
