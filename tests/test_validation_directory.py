#!/usr/bin/env python3
"""
Script de validación para el módulo de escaneo web de directorios.

Este script realiza pruebas unitarias para verificar el correcto
funcionamiento del módulo de escaneo web de directorios.
"""

import os
import sys
import unittest
import tempfile
import json
from unittest.mock import patch, MagicMock

# Añadir el directorio raíz al path para importar los módulos
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from modules.web_directory_scanner import ScanResult, WordlistManager, DirectoryScanner, DirectoryReporter

class TestScanResult(unittest.TestCase):
    """Pruebas unitarias para la clase ScanResult."""
    
    def test_scan_result_creation(self):
        """Prueba la creación de un objeto ScanResult."""
        result = ScanResult("http://example.com/admin", 200, "text/html", 1024, 0.5)
        
        self.assertEqual(result.url, "http://example.com/admin")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.content_type, "text/html")
        self.assertEqual(result.content_length, 1024)
        self.assertEqual(result.response_time, 0.5)
        self.assertFalse(result.interesting)
        
    def test_status_code_methods(self):
        """Prueba los métodos de verificación de código de estado."""
        # Éxito (2xx)
        result = ScanResult("http://example.com/page", 200)
        self.assertTrue(result.is_success())
        self.assertFalse(result.is_redirect())
        self.assertFalse(result.is_client_error())
        self.assertFalse(result.is_server_error())
        
        # Redirección (3xx)
        result = ScanResult("http://example.com/redirect", 301)
        self.assertFalse(result.is_success())
        self.assertTrue(result.is_redirect())
        self.assertFalse(result.is_client_error())
        self.assertFalse(result.is_server_error())
        
        # Error de cliente (4xx)
        result = ScanResult("http://example.com/notfound", 404)
        self.assertFalse(result.is_success())
        self.assertFalse(result.is_redirect())
        self.assertTrue(result.is_client_error())
        self.assertFalse(result.is_server_error())
        
        # Error de servidor (5xx)
        result = ScanResult("http://example.com/error", 500)
        self.assertFalse(result.is_success())
        self.assertFalse(result.is_redirect())
        self.assertFalse(result.is_client_error())
        self.assertTrue(result.is_server_error())
        
    def test_mark_interesting(self):
        """Prueba marcar un resultado como interesante."""
        result = ScanResult("http://example.com/secret", 200)
        self.assertFalse(result.interesting)
        
        result.mark_interesting("Contiene información sensible")
        self.assertTrue(result.interesting)
        self.assertEqual(len(result.notes), 1)
        self.assertIn("Contiene información sensible", result.notes[0])
        
    def test_add_note(self):
        """Prueba añadir notas a un resultado."""
        result = ScanResult("http://example.com/page", 200)
        self.assertEqual(len(result.notes), 0)
        
        result.add_note("Esta es una nota")
        result.add_note("Esta es otra nota")
        
        self.assertEqual(len(result.notes), 2)
        self.assertEqual(result.notes[0], "Esta es una nota")
        self.assertEqual(result.notes[1], "Esta es otra nota")
        
    def test_to_dict(self):
        """Prueba la conversión a diccionario."""
        result = ScanResult("http://example.com/admin", 200, "text/html", 1024, 0.5)
        result.add_note("Nota de prueba")
        result.mark_interesting("Razón de prueba")
        
        result_dict = result.to_dict()
        
        self.assertEqual(result_dict['url'], "http://example.com/admin")
        self.assertEqual(result_dict['status_code'], 200)
        self.assertEqual(result_dict['content_type'], "text/html")
        self.assertEqual(result_dict['content_length'], 1024)
        self.assertEqual(result_dict['response_time'], 0.5)
        self.assertTrue(result_dict['interesting'])
        self.assertEqual(len(result_dict['notes']), 2)

class TestWordlistManager(unittest.TestCase):
    """Pruebas unitarias para la clase WordlistManager."""
    
    def setUp(self):
        """Configuración inicial para las pruebas."""
        # Crear directorio temporal para diccionarios
        self.temp_dir = tempfile.mkdtemp()
        self.wordlist_manager = WordlistManager(wordlists_dir=self.temp_dir, log_level=30)  # WARNING level
        
        # Crear algunos diccionarios de prueba
        self.test_words = ['admin', 'login', 'test', 'backup', 'config']
        
        with open(os.path.join(self.temp_dir, 'test.txt'), 'w') as f:
            f.write('\n'.join(self.test_words))
            
        with open(os.path.join(self.temp_dir, 'empty.txt'), 'w') as f:
            f.write('')
        
    def tearDown(self):
        """Limpieza después de las pruebas."""
        import shutil
        shutil.rmtree(self.temp_dir)
        
    def test_discover_wordlists(self):
        """Prueba el descubrimiento de diccionarios."""
        # Forzar redescubrimiento
        self.wordlist_manager._discover_wordlists()
        
        available = self.wordlist_manager.get_available_wordlists()
        self.assertIn('test.txt', available)
        self.assertIn('empty.txt', available)
        self.assertEqual(available['test.txt']['lines'], 5)
        
    def test_load_wordlist(self):
        """Prueba la carga de un diccionario."""
        words = self.wordlist_manager.load_wordlist('test.txt')
        
        self.assertEqual(len(words), 5)
        self.assertEqual(words, self.test_words)
        
        # Probar con un diccionario que no existe
        words = self.wordlist_manager.load_wordlist('nonexistent.txt')
        self.assertIsNone(words)
        
    def test_filter_wordlist(self):
        """Prueba el filtrado de un diccionario."""
        words = self.test_words.copy()
        
        # Filtrar por longitud mínima
        filtered = self.wordlist_manager.filter_wordlist(words, min_length=5)
        self.assertEqual(len(filtered), 3)
        self.assertIn('login', filtered)
        self.assertIn('admin', filtered)
        self.assertIn('backup', filtered)
        self.assertNotIn('test', filtered)
        
        # Filtrar por longitud máxima
        filtered = self.wordlist_manager.filter_wordlist(words, max_length=4)
        self.assertEqual(len(filtered), 2)
        self.assertIn('test', filtered)
        
        # Filtrar por patrón
        filtered = self.wordlist_manager.filter_wordlist(words, pattern='^[ab]')
        self.assertEqual(len(filtered), 2)
        self.assertIn('admin', filtered)
        self.assertIn('backup', filtered)
        
    def test_save_wordlist(self):
        """Prueba guardar un diccionario."""
        words = ['word1', 'word2', 'word3']
        
        result = self.wordlist_manager.save_wordlist(words, 'new_wordlist')
        self.assertTrue(result)
        
        # Verificar que se guardó correctamente
        filepath = os.path.join(self.temp_dir, 'new_wordlist.txt')
        self.assertTrue(os.path.exists(filepath))
        
        # Verificar contenido
        with open(filepath, 'r') as f:
            content = f.read().strip().split('\n')
            self.assertEqual(content, words)
            
    def test_generate_extensions_list(self):
        """Prueba la generación de listas de extensiones."""
        # Extensiones comunes
        extensions = self.wordlist_manager.generate_extensions_list()
        self.assertIn('html', extensions)
        self.assertIn('php', extensions)
        
        # Extensiones PHP
        extensions = self.wordlist_manager.generate_extensions_list('php')
        self.assertIn('php', extensions)
        self.assertIn('phtml', extensions)
        
        # Extensiones de backup
        extensions = self.wordlist_manager.generate_extensions_list('backup')
        self.assertIn('bak', extensions)
        self.assertIn('old', extensions)
        
    def test_add_common_prefixes_suffixes(self):
        """Prueba añadir prefijos y sufijos comunes."""
        words = ['admin', 'login']
        
        expanded = self.wordlist_manager.add_common_prefixes_suffixes(words)
        
        # Verificar que se añadieron prefijos
        self.assertIn('dev_admin', expanded)
        self.assertIn('test_login', expanded)
        
        # Verificar que se añadieron sufijos
        self.assertIn('admin_backup', expanded)
        self.assertIn('login_1', expanded)
        
        # Verificar que se mantuvieron las palabras originales
        self.assertIn('admin', expanded)
        self.assertIn('login', expanded)

class TestDirectoryScanner(unittest.TestCase):
    """Pruebas unitarias para la clase DirectoryScanner."""
    
    def setUp(self):
        """Configuración inicial para las pruebas."""
        # Crear mock de WordlistManager
        self.mock_wordlist_manager = MagicMock()
        self.scanner = DirectoryScanner(wordlist_manager=self.mock_wordlist_manager, log_level=30)  # WARNING level
        
    @patch('requests.get')
    def test_scan_url(self, mock_get):
        """Prueba el escaneo de una URL específica."""
        # Configurar el mock
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_response.content = b'<html><body>Test page</body></html>'
        mock_response.text = '<html><body>Test page</body></html>'
        mock_response.elapsed.total_seconds.return_value = 0.1
        mock_get.return_value = mock_response
        
        # Realizar escaneo
        result = self.scanner.scan_url('http://example.com', 'admin')
        
        # Verificar resultado
        self.assertIsNotNone(result)
        self.assertEqual(result.url, 'http://example.com/admin')
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.content_type, 'text/html')
        self.assertEqual(result.content_length, len(mock_response.content))
        
        # Verificar que se llamó a requests.get con los parámetros correctos
        mock_get.assert_called_once()
        args, kwargs = mock_get.call_args
        self.assertEqual(args[0], 'http://example.com/admin')
        
    @patch('requests.get')
    def test_scan_url_with_error(self, mock_get):
        """Prueba el escaneo de una URL con error."""
        # Configurar el mock para simular un timeout
        mock_get.side_effect = requests.exceptions.Timeout()
        
        # Realizar escaneo
        result = self.scanner.scan_url('http://example.com', 'admin')
        
        # Verificar resultado
        self.assertIsNone(result)
        
    @patch('requests.get')
    def test_scan_with_wordlist(self, mock_get):
        """Prueba el escaneo con un diccionario."""
        # Configurar el mock
        def mock_response(url):
            response = MagicMock()
            if 'admin' in url:
                response.status_code = 200
                response.interesting = True
            elif 'login' in url:
                response.status_code = 200
            else:
                response.status_code = 404
            response.headers = {'Content-Type': 'text/html'}
            response.content = b'<html><body>Test page</body></html>'
            response.text = '<html><body>Test page</body></html>'
            response.elapsed.total_seconds.return_value = 0.1
            return response
            
        mock_get.side_effect = mock_response
        
        # Configurar wordlist
        wordlist = ['admin', 'login', 'test']
        
        # Realizar escaneo
        with patch.object(self.scanner, 'scan_url', wraps=self.scanner.scan_url) as mock_scan_url:
            results = self.scanner.scan_with_wordlist('http://example.com', wordlist, threads=1)
            
            # Verificar que se llamó a scan_url para cada palabra
            self.assertEqual(mock_scan_url.call_count, 3)
            
            # Verificar resultados
            self.assertEqual(len(results), 3)  # Todos los resultados, incluso 404
            success_results = [r for r in results if r.is_success()]
            self.assertEqual(len(success_results), 2)
            
    def test_save_load_results(self):
        """Prueba guardar y cargar resultados."""
        # Crear resultados de prueba
        result1 = ScanResult("http://example.com/admin", 200, "text/html", 1024, 0.5)
        result1.mark_interesting("Admin page")
        
        result2 = ScanResult("http://example.com/login", 200, "text/html", 512, 0.3)
        
        results = [result1, result2]
        
        # Guardar resultados
        fd, temp_path = tempfile.mkstemp(suffix='.json')
        os.close(fd)
        
        save_result = self.scanner.save_results(results, temp_path)
        self.assertTrue(save_result)
        
        # Cargar resultados
        loaded_results = self.scanner.load_results(temp_path)
        
        # Verificar resultados
        self.assertEqual(len(loaded_results), 2)
        self.assertEqual(loaded_results[0].url, "http://example.com/admin")
        self.assertTrue(loaded_results[0].interesting)
        self.assertEqual(loaded_results[1].url, "http://example.com/login")
        
        # Limpiar
        os.unlink(temp_path)

class TestDirectoryReporter(unittest.TestCase):
    """Pruebas unitarias para la clase DirectoryReporter."""
    
    def setUp(self):
        """Configuración inicial para las pruebas."""
        self.temp_dir = tempfile.mkdtemp()
        self.reporter = DirectoryReporter(output_dir=self.temp_dir, log_level=30)  # WARNING level
        
        # Crear resultados de prueba
        self.result1 = ScanResult("http://example.com/admin", 200, "text/html", 1024, 0.5)
        self.result1.mark_interesting("Admin page")
        
        self.result2 = ScanResult("http://example.com/login", 200, "text/html", 512, 0.3)
        
        self.result3 = ScanResult("http://example.com/notfound", 404, "text/html", 256, 0.2)
        
        self.results = [self.result1, self.result2, self.result3]
        
    def tearDown(self):
        """Limpieza después de las pruebas."""
        import shutil
        shutil.rmtree(self.temp_dir)
        
    def test_generate_text_report(self):
        """Prueba la generación de informes de texto."""
        report_file = self.reporter.generate_text_report(self.results, "http://example.com")
        
        # Verificar que se creó el archivo
        self.assertTrue(os.path.exists(report_file))
        
        # Verificar contenido básico
        with open(report_file, 'r') as f:
            content = f.read()
            self.assertIn("INFORME DE ESCANEO DE DIRECTORIOS WEB", content)
            self.assertIn("http://example.com/admin", content)
            self.assertIn("http://example.com/login", content)
            self.assertIn("http://example.com/notfound", content)
            
    def test_generate_json_report(self):
        """Prueba la generación de informes JSON."""
        report_file = self.reporter.generate_json_report(self.results, "http://example.com")
        
        # Verificar que se creó el archivo
        self.assertTrue(os.path.exists(report_file))
        
        # Verificar contenido básico
        with open(report_file, 'r') as f:
            data = json.load(f)
            self.assertIn("metadata", data)
            self.assertIn("results", data)
            self.assertEqual(len(data["results"]), 3)
            self.assertEqual(data["metadata"]["success_count"], 2)
            self.assertEqual(data["metadata"]["interesting_count"], 1)
            
    def test_generate_complete_report(self):
        """Prueba la generación de informes completos."""
        report_files = self.reporter.generate_complete_report(self.results, "http://example.com")
        
        # Verificar que se crearon los archivos
        self.assertIn('text', report_files)
        self.assertIn('html', report_files)
        self.assertIn('json', report_files)
        
        for file_path in report_files.values():
            self.assertTrue(os.path.exists(file_path))

if __name__ == '__main__':
    unittest.main()
