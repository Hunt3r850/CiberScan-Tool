"""
Clase CVEDatabase para gestionar la base de datos de vulnerabilidades CVE.

Esta clase proporciona métodos para buscar, actualizar y gestionar
información sobre vulnerabilidades conocidas (CVE).
"""

import os
import json
import logging
import requests
import datetime
import sqlite3
from .vulnerability import Vulnerability

class CVEDatabase:
    def __init__(self, db_path=None, log_level=logging.INFO):
        """
        Inicializa un nuevo objeto CVEDatabase.
        
        Args:
            db_path (str, opcional): Ruta al archivo de base de datos SQLite
            log_level (int, opcional): Nivel de logging
        """
        if db_path is None:
            # Usar una ubicación predeterminada si no se especifica
            db_path = os.path.join(os.path.dirname(__file__), '../../../data/cve_database.db')
            
        self.db_path = db_path
        self.logger = self._setup_logger(log_level)
        self._ensure_db_exists()
        
    def _setup_logger(self, log_level):
        """
        Configura el logger para la base de datos.
        
        Args:
            log_level (int): Nivel de logging
            
        Returns:
            Logger: Objeto logger configurado
        """
        logger = logging.getLogger("CVEDatabase")
        logger.setLevel(log_level)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger
        
    def _ensure_db_exists(self):
        """
        Asegura que la base de datos existe y tiene la estructura correcta.
        """
        # Crear directorio si no existe
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        # Conectar a la base de datos
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Crear tablas si no existen
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT,
            cvss_score REAL,
            severity TEXT,
            mitigation TEXT,
            last_updated TEXT
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS references (
            vuln_id TEXT,
            reference TEXT,
            FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id),
            PRIMARY KEY (vuln_id, reference)
        )
        ''')
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"Base de datos inicializada en {self.db_path}")
        
    def search_by_id(self, vuln_id):
        """
        Busca una vulnerabilidad por su identificador.
        
        Args:
            vuln_id (str): Identificador de la vulnerabilidad (ej. CVE-2021-1234)
            
        Returns:
            Vulnerability: Objeto Vulnerability o None si no se encuentra
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Buscar la vulnerabilidad
        cursor.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,))
        result = cursor.fetchone()
        
        if not result:
            conn.close()
            return None
            
        # Crear objeto Vulnerability
        vuln = Vulnerability(
            vuln_id=result[0],
            name=result[1],
            description=result[2],
            cvss_score=result[3]
        )
        
        vuln.mitigation = result[5]
        
        # Obtener referencias
        cursor.execute("SELECT reference FROM references WHERE vuln_id = ?", (vuln_id,))
        references = cursor.fetchall()
        
        for ref in references:
            vuln.add_reference(ref[0])
            
        conn.close()
        return vuln
        
    def search_by_keyword(self, keyword):
        """
        Busca vulnerabilidades por palabra clave.
        
        Args:
            keyword (str): Palabra clave a buscar
            
        Returns:
            list: Lista de objetos Vulnerability que coinciden
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Buscar vulnerabilidades que coincidan con la palabra clave
        cursor.execute("""
        SELECT id FROM vulnerabilities 
        WHERE name LIKE ? OR description LIKE ?
        """, (f"%{keyword}%", f"%{keyword}%"))
        
        results = cursor.fetchall()
        conn.close()
        
        # Obtener objetos completos
        vulnerabilities = []
        for result in results:
            vuln = self.search_by_id(result[0])
            if vuln:
                vulnerabilities.append(vuln)
                
        return vulnerabilities
        
    def search_by_product(self, product, version=None):
        """
        Busca vulnerabilidades relacionadas con un producto específico.
        
        Args:
            product (str): Nombre del producto
            version (str, opcional): Versión específica del producto
            
        Returns:
            list: Lista de objetos Vulnerability que afectan al producto
        """
        # Esta implementación es simplificada
        # En un sistema real, se utilizaría una base de datos CPE más completa
        keyword = product
        if version:
            keyword += f" {version}"
            
        return self.search_by_keyword(keyword)
        
    def add_vulnerability(self, vulnerability):
        """
        Añade o actualiza una vulnerabilidad en la base de datos.
        
        Args:
            vulnerability (Vulnerability): Objeto Vulnerability a añadir
            
        Returns:
            bool: True si se añadió correctamente, False en caso contrario
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Insertar o actualizar la vulnerabilidad
            cursor.execute("""
            INSERT OR REPLACE INTO vulnerabilities 
            (id, name, description, cvss_score, severity, mitigation, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                vulnerability.vuln_id,
                vulnerability.name,
                vulnerability.description,
                vulnerability.cvss_score,
                vulnerability.severity,
                vulnerability.mitigation,
                datetime.datetime.now().isoformat()
            ))
            
            # Eliminar referencias antiguas
            cursor.execute("DELETE FROM references WHERE vuln_id = ?", (vulnerability.vuln_id,))
            
            # Insertar nuevas referencias
            for reference in vulnerability.references:
                cursor.execute("""
                INSERT INTO references (vuln_id, reference)
                VALUES (?, ?)
                """, (vulnerability.vuln_id, reference))
                
            conn.commit()
            self.logger.info(f"Vulnerabilidad {vulnerability.vuln_id} añadida/actualizada")
            return True
            
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error al añadir vulnerabilidad: {str(e)}")
            return False
            
        finally:
            conn.close()
            
    def update_from_nvd(self, days_back=30):
        """
        Actualiza la base de datos con información reciente del NVD (National Vulnerability Database).
        
        Args:
            days_back (int, opcional): Número de días hacia atrás para buscar actualizaciones
            
        Returns:
            int: Número de vulnerabilidades actualizadas
        """
        self.logger.info(f"Actualizando base de datos desde NVD (últimos {days_back} días)")
        
        # Calcular fecha de inicio
        start_date = datetime.datetime.now() - datetime.timedelta(days=days_back)
        start_date_str = start_date.strftime("%Y-%m-%d")
        
        # URL de la API de NVD
        url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?pubStartDate={start_date_str}T00:00:00:000 UTC-00:00"
        
        try:
            response = requests.get(url)
            if response.status_code != 200:
                self.logger.error(f"Error al obtener datos de NVD: {response.status_code}")
                return 0
                
            data = response.json()
            count = 0
            
            for item in data.get('result', {}).get('CVE_Items', []):
                try:
                    cve_id = item['cve']['CVE_data_meta']['ID']
                    
                    # Obtener descripción
                    description = ""
                    for desc_data in item['cve']['description']['description_data']:
                        if desc_data['lang'] == 'en':
                            description = desc_data['value']
                            break
                    
                    # Obtener puntuación CVSS
                    cvss_score = None
                    if 'baseMetricV3' in item['impact']:
                        cvss_score = item['impact']['baseMetricV3']['cvssV3']['baseScore']
                    elif 'baseMetricV2' in item['impact']:
                        cvss_score = item['impact']['baseMetricV2']['cvssV2']['baseScore']
                    
                    # Crear objeto Vulnerability
                    vuln = Vulnerability(
                        vuln_id=cve_id,
                        name=f"Vulnerability {cve_id}",
                        description=description,
                        cvss_score=cvss_score
                    )
                    
                    # Añadir referencias
                    for ref_data in item['cve']['references']['reference_data']:
                        vuln.add_reference(ref_data['url'])
                    
                    # Guardar en la base de datos
                    if self.add_vulnerability(vuln):
                        count += 1
                        
                except Exception as e:
                    self.logger.error(f"Error al procesar {cve_id}: {str(e)}")
                    continue
            
            self.logger.info(f"Actualizadas {count} vulnerabilidades desde NVD")
            return count
            
        except Exception as e:
            self.logger.error(f"Error al actualizar desde NVD: {str(e)}")
            return 0
            
    def get_statistics(self):
        """
        Obtiene estadísticas sobre la base de datos de vulnerabilidades.
        
        Returns:
            dict: Diccionario con estadísticas
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Total de vulnerabilidades
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        stats['total_vulnerabilities'] = cursor.fetchone()[0]
        
        # Vulnerabilidades por severidad
        cursor.execute("""
        SELECT severity, COUNT(*) FROM vulnerabilities
        GROUP BY severity
        """)
        stats['by_severity'] = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Vulnerabilidades añadidas recientemente (últimos 30 días)
        thirty_days_ago = (datetime.datetime.now() - datetime.timedelta(days=30)).isoformat()
        cursor.execute("""
        SELECT COUNT(*) FROM vulnerabilities
        WHERE last_updated > ?
        """, (thirty_days_ago,))
        stats['recent_vulnerabilities'] = cursor.fetchone()[0]
        
        conn.close()
        return stats
        
    def export_to_json(self, output_file):
        """
        Exporta la base de datos a un archivo JSON.
        
        Args:
            output_file (str): Ruta del archivo de salida
            
        Returns:
            bool: True si se exportó correctamente, False en caso contrario
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        try:
            # Obtener todas las vulnerabilidades
            cursor.execute("SELECT id FROM vulnerabilities")
            vuln_ids = [row['id'] for row in cursor.fetchall()]
            
            # Crear lista de vulnerabilidades
            vulnerabilities = []
            for vuln_id in vuln_ids:
                vuln = self.search_by_id(vuln_id)
                if vuln:
                    vulnerabilities.append(vuln.to_dict())
            
            # Guardar en archivo JSON
            with open(output_file, 'w') as f:
                json.dump(vulnerabilities, f, indent=4)
                
            self.logger.info(f"Base de datos exportada a {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error al exportar base de datos: {str(e)}")
            return False
            
        finally:
            conn.close()
            
    def import_from_json(self, input_file):
        """
        Importa vulnerabilidades desde un archivo JSON.
        
        Args:
            input_file (str): Ruta del archivo de entrada
            
        Returns:
            int: Número de vulnerabilidades importadas
        """
        try:
            with open(input_file, 'r') as f:
                data = json.load(f)
                
            count = 0
            for vuln_data in data:
                try:
                    vuln = Vulnerability(
                        vuln_id=vuln_data['vuln_id'],
                        name=vuln_data['name'],
                        description=vuln_data['description'],
                        cvss_score=vuln_data['cvss_score']
                    )
                    
                    if 'mitigation' in vuln_data and vuln_data['mitigation']:
                        vuln.set_mitigation(vuln_data['mitigation'])
                        
                    if 'references' in vuln_data:
                        for ref in vuln_data['references']:
                            vuln.add_reference(ref)
                            
                    if self.add_vulnerability(vuln):
                        count += 1
                        
                except Exception as e:
                    self.logger.error(f"Error al importar vulnerabilidad: {str(e)}")
                    continue
                    
            self.logger.info(f"Importadas {count} vulnerabilidades desde {input_file}")
            return count
            
        except Exception as e:
            self.logger.error(f"Error al importar desde JSON: {str(e)}")
            return 0
