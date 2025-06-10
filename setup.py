#!/usr/bin/env python3
"""
Script de instalación para la herramienta de ciberseguridad.

Este script verifica las dependencias necesarias e instala los paquetes requeridos
para el funcionamiento correcto de la herramienta, utilizando un entorno virtual.
"""

import os
import sys
import subprocess
import platform
import argparse
import shutil

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

def check_venv():
    """Verifica que el módulo venv esté disponible."""
    try:
        subprocess.run([sys.executable, "-m", "venv", "--help"], 
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        print("✓ Módulo venv detectado.")
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        print("Error: El módulo venv no está disponible.")
        print("Intente instalar el paquete python3-venv:")
        print("  - Ubuntu/Debian/Kali: sudo apt install python3-venv")
        print("  - CentOS/RHEL: sudo yum install python3-venv")
        print("  - Fedora: sudo dnf install python3-venv")
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

def create_virtual_environment(venv_dir="venv"):
    """Crea un entorno virtual de Python."""
    if os.path.exists(venv_dir):
        print(f"El entorno virtual {venv_dir} ya existe.")
        response = input("¿Desea recrearlo? (s/N): ")
        if response.lower() == 's':
            print(f"Eliminando entorno virtual existente {venv_dir}...")
            try:
                shutil.rmtree(venv_dir)
            except Exception as e:
                print(f"Error al eliminar el entorno virtual: {e}")
                return False
        else:
            print(f"Usando entorno virtual existente {venv_dir}.")
            return True
    
    print(f"Creando entorno virtual en {venv_dir}...")
    try:
        subprocess.run([sys.executable, "-m", "venv", venv_dir], check=True)
        print(f"✓ Entorno virtual creado en {venv_dir}")
        return True
    except subprocess.SubprocessError as e:
        print(f"Error al crear el entorno virtual: {e}")
        return False

def get_venv_python_path(venv_dir="venv"):
    """Obtiene la ruta al ejecutable de Python en el entorno virtual."""
    if os.name == "nt":  # Windows
        return os.path.join(venv_dir, "Scripts", "python")
    else:  # Unix/Linux/Mac
        return os.path.join(venv_dir, "bin", "python")

def get_venv_pip_path(venv_dir="venv"):
    """Obtiene la ruta al ejecutable de pip en el entorno virtual."""
    if os.name == "nt":  # Windows
        return os.path.join(venv_dir, "Scripts", "pip")
    else:  # Unix/Linux/Mac
        return os.path.join(venv_dir, "bin", "pip")

def install_python_dependencies(venv_dir="venv", requirements_file="requirements.txt"):
    """Instala las dependencias de Python desde el archivo requirements.txt en el entorno virtual."""
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
    
    venv_pip = get_venv_pip_path(venv_dir)
    
    print(f"Instalando dependencias de Python desde {requirements_file} en el entorno virtual...")
    try:
        subprocess.run([venv_pip, "install", "-r", requirements_file], check=True)
        print("✓ Dependencias de Python instaladas correctamente en el entorno virtual.")
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
    venv_python = get_venv_python_path()
    try:
        # Intentar importar la API de Python de ZAP en el entorno virtual
        result = subprocess.run([venv_python, "-c", "import zapv2; print('ZAP API detectada')"], 
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if "ZAP API detectada" in result.stdout.decode('utf-8'):
            print("✓ API de Python para OWASP ZAP detectada.")
        else:
            print("Nota: API de Python para OWASP ZAP no está instalada. Esta herramienta es opcional pero recomendada.")
    except (subprocess.SubprocessError, FileNotFoundError):
        print("Nota: API de Python para OWASP ZAP no está instalada. Esta herramienta es opcional pero recomendada.")

def create_activation_scripts(venv_dir="venv"):
    """Crea scripts de activación para facilitar el uso del entorno virtual."""
    # Script para Unix/Linux/Mac
    activate_sh = "activate.sh"
    with open(activate_sh, 'w') as f:
        f.write(f'''#!/bin/bash
# Script para activar el entorno virtual
source {venv_dir}/bin/activate
echo "Entorno virtual activado. Ejecute 'deactivate' para salir."
''')
    os.chmod(activate_sh, 0o755)
    
    # Script para Windows
    activate_bat = "activate.bat"
    with open(activate_bat, 'w') as f:
        f.write(f'''@echo off
:: Script para activar el entorno virtual
call {venv_dir}\\Scripts\\activate.bat
echo Entorno virtual activado. Ejecute 'deactivate' para salir.
''')
    
    print(f"✓ Scripts de activación creados: {activate_sh} y {activate_bat}")
    return True

def create_run_script(venv_dir="venv"):
    """Crea un script para ejecutar la herramienta desde el entorno virtual."""
    # Script para Unix/Linux/Mac
    run_sh = "run.sh"
    with open(run_sh, 'w') as f:
        f.write(f'''#!/bin/bash
# Script para ejecutar la herramienta desde el entorno virtual
source {venv_dir}/bin/activate
python3 src/cibersecurity_tool.py "$@"
''')
    os.chmod(run_sh, 0o755)
    
    # Script para Windows
    run_bat = "run.bat"
    with open(run_bat, 'w') as f:
        f.write(f'''@echo off
:: Script para ejecutar la herramienta desde el entorno virtual
call {venv_dir}\\Scripts\\activate.bat
python src\\cibersecurity_tool.py %*
''')
    
    print(f"✓ Scripts de ejecución creados: {run_sh} y {run_bat}")
    return True

def main():
    parser = argparse.ArgumentParser(description='Instalador de la herramienta de ciberseguridad')
    parser.add_argument('--skip-checks', action='store_true', help='Omitir verificaciones de requisitos')
    parser.add_argument('--skip-dependencies', action='store_true', help='Omitir instalación de dependencias')
    parser.add_argument('--venv-dir', default='venv', help='Directorio para el entorno virtual')
    args = parser.parse_args()
    
    print("=== Instalador de la Herramienta de Ciberseguridad ===\n")
    
    if not args.skip_checks:
        print("Verificando requisitos del sistema...")
        python_ok = check_python_version()
        pip_ok = check_pip()
        venv_ok = check_venv()
        nmap_ok = check_nmap()
        
        if not (python_ok and pip_ok and venv_ok):
            print("\nError: No se cumplen los requisitos mínimos. Por favor, instale las dependencias faltantes.")
            return 1
        
        if not nmap_ok:
            print("\nAdvertencia: Nmap no está instalado o no está en el PATH.")
            print("Nmap es necesario para el funcionamiento completo de la herramienta.")
            print("Por favor, instale Nmap:")
            print("  - Ubuntu/Debian/Kali: sudo apt install nmap")
            print("  - CentOS/RHEL: sudo yum install nmap")
            print("  - Windows: Descargue e instale desde https://nmap.org/download.html")
            
            proceed = input("\n¿Desea continuar con la instalación sin Nmap? (s/N): ")
            if proceed.lower() != 's':
                return 1
    
    if not args.skip_dependencies:
        print("\nCreando entorno virtual...")
        if not create_virtual_environment(args.venv_dir):
            print("\nError: No se pudo crear el entorno virtual.")
            return 1
        
        print("\nInstalando dependencias...")
        if not install_python_dependencies(args.venv_dir):
            print("\nError: No se pudieron instalar todas las dependencias.")
            return 1
    
    print("\nCreando estructura de directorios...")
    create_directory_structure()
    
    print("\nCreando archivos de datos iniciales...")
    create_common_wordlist()
    
    print("\nCreando scripts de activación y ejecución...")
    create_activation_scripts(args.venv_dir)
    create_run_script(args.venv_dir)
    
    print("\nVerificando herramientas opcionales...")
    check_optional_tools()
    
    print("\n=== Instalación completada con éxito ===")
    print("\nPara activar el entorno virtual, ejecute:")
    if os.name == "nt":  # Windows
        print(f"  .\\activate.bat")
    else:  # Unix/Linux/Mac
        print(f"  source ./activate.sh")
    
    print("\nPara ejecutar la herramienta, use:")
    if os.name == "nt":  # Windows
        print(f"  .\\run.bat [opciones]")
    else:  # Unix/Linux/Mac
        print(f"  ./run.sh [opciones]")
    
    print("\nPara más información, consulte:")
    print("  - README.md: Información general del proyecto")
    print("  - docs/manual_usuario.md: Manual de usuario")
    print("  - docs/documentacion_tecnica.md: Documentación técnica")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
