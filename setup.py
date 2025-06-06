#!/usr/bin/env python3
"""
Script de instalación para la herramienta de ciberseguridad.

Este script verifica las dependencias necesarias e instala los paquetes requeridos
para el funcionamiento correcto de la herramienta.
"""

import os
import sys
import subprocess
import platform
import argparse

def check_python_version():
    """Verifica que la versión de Python sea 3.8 o superior."""
    required_version = (3, 8)
    current_version = sys.version_info
    
    if current_version < required_version:
        print(f"Error: Se requiere Python {required_version[0]}.{required_version[1]} o superior.")
        print(f"Versión actual: {current_version[0]}.{current_version[1]}.{current_version[2]}")
        return False
    
    print(f"✓ Python {current_version[0]}.{current_version[1]}.{current_version[2]} detectado.")
    return True

def check_pip():
    """Verifica que pip esté instalado."""
    try:
        subprocess.run([sys.executable, "-m", "pip", "--version"], 
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        print("✓ Pip detectado.")
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        print("Error: Pip no está instalado o no está en el PATH.")
        return False

def check_nmap():
    """Verifica que Nmap esté instalado."""
    try:
        result = subprocess.run(["nmap", "--version"], 
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            version = result.stdout.decode('utf-8').split('\n')[0]
            print(f"✓ {version}")
            return True
        else:
            print("Error: Nmap no está instalado o no está en el PATH.")
            return False
    except (subprocess.SubprocessError, FileNotFoundError):
        print("Error: Nmap no está instalado o no está en el PATH.")
        return False

def install_python_dependencies(requirements_file="requirements.txt"):
    """Instala las dependencias de Python desde el archivo requirements.txt."""
    if not os.path.exists(requirements_file):
        # Crear archivo requirements.txt si no existe
        with open(requirements_file, 'w') as f:
            f.write('\n'.join([
                "python-nmap>=0.7.1",
                "matplotlib>=3.5.0",
                "networkx>=2.6.3",
                "requests>=2.26.0",
                "beautifulsoup4>=4.10.0",
                "tqdm>=4.62.3",
                "python-owasp-zap-v2.4>=0.0.20"
            ]))
        print(f"Archivo {requirements_file} creado.")
    
    print(f"Instalando dependencias de Python desde {requirements_file}...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", requirements_file], check=True)
        print("✓ Dependencias de Python instaladas correctamente.")
        return True
    except subprocess.SubprocessError as e:
        print(f"Error al instalar dependencias de Python: {e}")
        return False

def create_directory_structure():
    """Crea la estructura de directorios necesaria."""
    directories = [
        "data/wordlists",
        "output"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    print("✓ Estructura de directorios creada.")
    return True

def create_common_wordlist():
    """Crea un diccionario común para escaneo de directorios."""
    wordlist_path = "data/wordlists/common.txt"
    
    if not os.path.exists(wordlist_path):
        with open(wordlist_path, 'w') as f:
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
        print(f"✓ Diccionario común creado en {wordlist_path}")
    else:
        print(f"✓ Diccionario común ya existe en {wordlist_path}")
    
    return True

def check_optional_tools():
    """Verifica la disponibilidad de herramientas opcionales."""
    # Verificar Nikto
    try:
        result = subprocess.run(["nikto", "-Version"], 
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            print("✓ Nikto detectado.")
        else:
            print("Nota: Nikto no está instalado. Esta herramienta es opcional pero recomendada.")
    except (subprocess.SubprocessError, FileNotFoundError):
        print("Nota: Nikto no está instalado. Esta herramienta es opcional pero recomendada.")
    
    # Verificar OWASP ZAP
    try:
        # Intentar importar la API de Python de ZAP
        import zapv2
        print("✓ API de Python para OWASP ZAP detectada.")
    except ImportError:
        print("Nota: API de Python para OWASP ZAP no está instalada. Esta herramienta es opcional pero recomendada.")

def main():
    parser = argparse.ArgumentParser(description='Instalador de la herramienta de ciberseguridad')
    parser.add_argument('--skip-checks', action='store_true', help='Omitir verificaciones de requisitos')
    parser.add_argument('--skip-dependencies', action='store_true', help='Omitir instalación de dependencias')
    args = parser.parse_args()
    
    print("=== Instalador de la Herramienta de Ciberseguridad ===\n")
    
    if not args.skip_checks:
        print("Verificando requisitos del sistema...")
        python_ok = check_python_version()
        pip_ok = check_pip()
        nmap_ok = check_nmap()
        
        if not (python_ok and pip_ok):
            print("\nError: No se cumplen los requisitos mínimos. Por favor, instale las dependencias faltantes.")
            return 1
        
        if not nmap_ok:
            print("\nAdvertencia: Nmap no está instalado o no está en el PATH.")
            print("Nmap es necesario para el funcionamiento completo de la herramienta.")
            print("Por favor, instale Nmap:")
            print("  - Ubuntu/Debian: sudo apt install nmap")
            print("  - CentOS/RHEL: sudo yum install nmap")
            print("  - Windows: Descargue e instale desde https://nmap.org/download.html")
            
            proceed = input("\n¿Desea continuar con la instalación sin Nmap? (s/N): ")
            if proceed.lower() != 's':
                return 1
    
    if not args.skip_dependencies:
        print("\nInstalando dependencias...")
        if not install_python_dependencies():
            print("\nError: No se pudieron instalar todas las dependencias.")
            return 1
    
    print("\nCreando estructura de directorios...")
    create_directory_structure()
    
    print("\nCreando archivos de datos iniciales...")
    create_common_wordlist()
    
    print("\nVerificando herramientas opcionales...")
    check_optional_tools()
    
    print("\n=== Instalación completada con éxito ===")
    print("\nPara verificar la instalación, ejecute:")
    print("  python3 src/cibersecurity_tool.py --help")
    print("\nPara más información, consulte:")
    print("  - README.md: Información general del proyecto")
    print("  - docs/manual_usuario.md: Manual de usuario")
    print("  - docs/documentacion_tecnica.md: Documentación técnica")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
