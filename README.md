# Ciberseguridad Automatizada

Este repositorio contiene una herramienta de ciberseguridad automatizada que integra múltiples módulos para realizar análisis completos de seguridad en sistemas y aplicaciones web.

## Características Principales

- **Escaneo de Redes**: Descubrimiento de hosts, puertos abiertos, servicios en ejecución y sistemas operativos.
- **Análisis de Vulnerabilidades**: Detección de vulnerabilidades conocidas en servicios y sistemas.
- **Escaneo Web de Directorios**: Descubrimiento de recursos ocultos en aplicaciones web.
- **Análisis de Vulnerabilidades Web**: Detección de problemas de seguridad como XSS, SQL Injection, Open Redirect y más.
- **Generación Automática de Informes**: Creación de informes detallados en múltiples formatos (texto, HTML, JSON).
- **Visualización de Resultados**: Representación gráfica de la topología de red y estadísticas de vulnerabilidades.

## Instalación

### Requisitos

- Python 3.8 o superior
- Pip (gestor de paquetes de Python)
- Nmap 7.80 o superior
- Opcional: Nikto, OWASP ZAP

### Pasos de Instalación

1. Clonar el repositorio:
   ```bash
   git clone https://github.com/Hunt3r850/CiberScan-Tool.git
   cd CiberScan-Tool
   ```

2. Ejecutar el script de instalación:
   ```bash
   python3 setup.py
   ```

3. Verificar la instalación:
   ```bash
   python3 src/cibersecurity_tool.py --help
   ```

## Uso Básico

### Escaneo Completo

```bash
python3 src/cibersecurity_tool.py --target 192.168.1.0/24 --web-url http://ejemplo.com --scan-type normal --output ./resultados
```

### Opciones Disponibles

- `--target`: Objetivo a escanear (IP, rango de IPs o dominio)
- `--web-url`: URL del sitio web (si es diferente del target)
- `--scan-type`: Tipo de escaneo de red ('fast', 'normal', 'deep')
- `--ports`: Puertos a escanear (ej. "22,80,443" o "1-1000")
- `--wordlist`: Nombre o ruta del diccionario para escaneo de directorios
- `--extensions`: Lista de extensiones para escaneo de directorios, separadas por comas
- `--threads`: Número de hilos para escaneo paralelo
- `--crawl-depth`: Profundidad de rastreo para análisis de vulnerabilidades web
- `--max-urls`: Número máximo de URLs a analizar
- `--scan-types`: Tipos de escaneo de vulnerabilidades web, separados por comas
- `--output`: Directorio de salida
- `--log-level`: Nivel de logging ('DEBUG', 'INFO', 'WARNING', 'ERROR')

## Documentación

Para más información, consulte:

- [Manual de Usuario](Manual_de_Usuario-Herramienta_de_Ciberseguridad.md): Guía detallada para usuarios finales.
- [Documentación Técnica](Documentación_Técnica-Herramienta_de_Ciberseguridad.md): Información técnica para desarrolladores y administradores.

## Consideraciones Éticas y Legales

Esta herramienta está diseñada para fines educativos y de seguridad legítima. Utilícela de manera ética y legal, respetando las políticas de seguridad y privacidad aplicables.

## Licencia

Este proyecto se distribuye bajo la licencia MIT.
