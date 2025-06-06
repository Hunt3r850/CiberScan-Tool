#!/usr/bin/env python3
"""
Script de prueba para el módulo de escaneo web de directorios.

Este script demuestra el uso del módulo de escaneo web de directorios
para descubrir recursos en aplicaciones web.
"""

import os
import sys
import logging
import argparse
import json

# Añadir el directorio raíz al path para importar los módulos
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from modules.web_directory_scanner import DirectoryScanner, WordlistManager, DirectoryReporter

def main():
    # Configurar logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger("DirectoryScanTest")
    
    # Parsear argumentos
    parser = argparse.ArgumentParser(description='Herramienta de escaneo web de directorios')
    parser.add_argument('--url', required=True, help='URL base del sitio web a escanear')
    parser.add_argument('--wordlist', default='common.txt', help='Nombre o ruta del diccionario a utilizar')
    parser.add_argument('--method', default='native', choices=['native', 'gobuster', 'wfuzz'], help='Método de escaneo')
    parser.add_argument('--extensions', help='Lista de extensiones separadas por comas')
    parser.add_argument('--threads', type=int, default=10, help='Número de hilos para escaneo paralelo')
    parser.add_argument('--output', default='./output', help='Directorio de salida')
    parser.add_argument('--delay', type=float, default=0.1, help='Retraso entre peticiones en segundos')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout para peticiones en segundos')
    parser.add_argument('--follow-redirects', action='store_true', help='Seguir redirecciones')
    args = parser.parse_args()
    
    # Crear directorio de salida si no existe
    if not os.path.exists(args.output):
        os.makedirs(args.output)
    
    # Crear directorio de diccionarios si no existe
    wordlists_dir = os.path.join(os.path.dirname(__file__), '../../data/wordlists')
    if not os.path.exists(wordlists_dir):
        os.makedirs(wordlists_dir)
        
    # Crear un diccionario de prueba si no existe ninguno
    common_wordlist = os.path.join(wordlists_dir, 'common.txt')
    if not os.path.exists(common_wordlist):
        logger.info("Creando diccionario de prueba")
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
                'uploads', 'private', 'public', 'secret', 'hidden',
                'backup', 'bak', 'old', 'new', 'archive', 'archives',
                'database', 'db', 'sql', 'mysql', 'oracle', 'mssql',
                'postgres', 'sqlite', 'mongo', 'mongodb', 'redis',
                'user', 'users', 'admin', 'administrator', 'root',
                'manager', 'manage', 'management', 'panel', 'console',
                'cp', 'cpanel', 'ftp', 'sftp', 'ssh', 'webmail',
                'mail', 'email', 'smtp', 'pop3', 'imap', 'calendar',
                'contact', 'about', 'aboutus', 'contact-us', 'contactus',
                'help', 'faq', 'support', 'ticket', 'tickets', 'knowledgebase'
            ]))
    
    # Inicializar gestor de diccionarios
    logger.info("Inicializando gestor de diccionarios")
    wordlist_manager = WordlistManager(wordlists_dir=wordlists_dir)
    
    # Inicializar escáner de directorios
    logger.info("Inicializando escáner de directorios")
    scanner = DirectoryScanner(wordlist_manager=wordlist_manager)
    
    # Configurar escáner
    scanner.set_delay(args.delay)
    scanner.set_timeout(args.timeout)
    scanner.set_follow_redirects(args.follow_redirects)
    
    # Preparar extensiones
    extensions = None
    if args.extensions:
        extensions = args.extensions.split(',')
    else:
        # Usar extensiones comunes por defecto
        extensions = wordlist_manager.generate_extensions_list("common")
    
    # Realizar escaneo
    logger.info(f"Iniciando escaneo de {args.url} con método {args.method}")
    results = scanner.scan_site(
        base_url=args.url,
        wordlist_name=args.wordlist,
        method=args.method,
        extensions=extensions,
        threads=args.threads
    )
    
    # Guardar resultados
    results_file = os.path.join(args.output, 'directory_scan_results.json')
    scanner.save_results(results, results_file)
    logger.info(f"Resultados guardados en {results_file}")
    
    # Generar informes
    logger.info("Generando informes")
    reporter = DirectoryReporter(output_dir=args.output)
    report_files = reporter.generate_complete_report(results, args.url)
    
    # Mostrar resumen
    success_count = sum(1 for r in results if r.is_success())
    interesting_count = sum(1 for r in results if r.interesting)
    logger.info(f"Escaneo completado. Se encontraron {len(results)} recursos, {success_count} exitosos, {interesting_count} interesantes.")
    
    # Mostrar archivos generados
    logger.info("Informes generados:")
    for format_name, file_path in report_files.items():
        logger.info(f"- {format_name}: {file_path}")
    
    # Mostrar resultados interesantes
    if interesting_count > 0:
        logger.info("\nResultados interesantes:")
        for result in [r for r in results if r.interesting]:
            logger.info(f"- {result}")

if __name__ == "__main__":
    main()
