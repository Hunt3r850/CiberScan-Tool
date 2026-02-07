# Herramienta de Ciberseguridad Automatizada

## Descripción General

Esta herramienta de ciberseguridad automatizada proporciona un conjunto integrado de funcionalidades para realizar análisis completos de seguridad en sistemas y aplicaciones web. Diseñada con una arquitectura modular, permite realizar desde escaneos básicos hasta análisis profundos de vulnerabilidades, adaptándose a diferentes necesidades y escenarios.

## Características Principales

- **Escaneo de Redes**: Descubrimiento de hosts, puertos abiertos, servicios en ejecución y sistemas operativos.
- **Análisis de Vulnerabilidades**: Detección de vulnerabilidades conocidas en servicios y sistemas.
- **Escaneo Web de Directorios**: Descubrimiento de recursos ocultos en aplicaciones web.
- **Análisis de Vulnerabilidades Web**: Detección de problemas de seguridad como XSS, SQL Injection, Open Redirect y más.
- **Generación Automática de Informes**: Creación de informes detallados en múltiples formatos (texto, HTML, JSON).
- **Visualización de Resultados**: Representación gráfica de la topología de red y estadísticas de vulnerabilidades.
- **Integración con Herramientas Externas**: Compatibilidad con Nikto, OWASP ZAP y otras herramientas de seguridad.

## Arquitectura

La herramienta está diseñada con una arquitectura modular que permite la fácil extensión y mantenimiento:

```
ciberseguridad_proyecto/
├── src/
│   ├── modules/
│   │   ├── network_scanner/       # Módulo de escaneo de redes
│   │   ├── vulnerability_scanner/ # Módulo de análisis de vulnerabilidades
│   │   ├── web_directory_scanner/ # Módulo de escaneo web de directorios
│   │   └── web_vulnerability_scanner/ # Módulo de análisis de vulnerabilidades web
│   ├── cibersecurity_tool.py      # Script principal de automatización
│   ├── test_network_scanner.py    # Scripts de prueba para cada módulo
│   ├── test_vulnerability_scanner.py
│   ├── test_directory_scanner.py
│   └── test_web_vulnerability_scanner.py
├── data/
│   └── wordlists/                 # Diccionarios para escaneo de directorios
└── docs/                          # Documentación
```

## Requisitos del Sistema

### Requisitos de Hardware
- CPU: 2 núcleos o más
- RAM: 4GB mínimo, 8GB recomendado
- Almacenamiento: 1GB de espacio libre

### Requisitos de Software
- Sistema Operativo: Linux (Ubuntu 20.04+), Windows 10+ o macOS 10.15+
- Python 3.8 o superior
- Pip (gestor de paquetes de Python)
- Nmap 7.80 o superior (para escaneo de redes)
- Opcional: Nikto, OWASP ZAP (para análisis avanzado de vulnerabilidades web)

## Instalación

### Instalación de Dependencias

1. Instalar Python 3.8+ y pip:
   ```bash
   # En Ubuntu/Debian
   sudo apt update
   sudo apt install python3 python3-pip
   
   # En CentOS/RHEL
   sudo yum install python3 python3-pip
   
   # En Windows
   # Descargar e instalar desde https://www.python.org/downloads/
   ```

2. Instalar Nmap:
   ```bash
   # En Ubuntu/Debian
   sudo apt install nmap
   
   # En CentOS/RHEL
   sudo yum install nmap
   
   # En Windows
   # Descargar e instalar desde https://nmap.org/download.html
   ```

3. Instalar dependencias de Python:
   ```bash
   pip3 install python-nmap matplotlib networkx requests beautifulsoup4 tqdm
   ```

4. Instalación opcional de herramientas adicionales:
   ```bash
   # Nikto (en Ubuntu/Debian)
   sudo apt install nikto
   
   # OWASP ZAP
   # Descargar desde https://www.zaproxy.org/download/
   pip3 install python-owasp-zap-v2.4
   ```

### Instalación de la Herramienta

1. Clonar o descargar el repositorio:
   ```bash
   git clone https://github.com/usuario/ciberseguridad_proyecto.git
   cd ciberseguridad_proyecto
   ```

2. Verificar la instalación:
   ```bash
   python3 src/cibersecurity_tool.py --help
   ```

## Uso Básico

### Escaneo Completo

Para realizar un análisis completo de seguridad:

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

## Ejemplos de Uso

### Escaneo Rápido de Red Local

```bash
python3 src/cibersecurity_tool.py --target 192.168.1.0/24 --scan-type fast --output ./resultados_red
```

### Análisis Profundo de un Servidor Web

```bash
python3 src/cibersecurity_tool.py --target example.com --web-url https://example.com --scan-type deep --crawl-depth 2 --max-urls 50 --output ./resultados_web
```

### Escaneo Personalizado

```bash
python3 src/cibersecurity_tool.py --target 10.0.0.1 --ports "22,80,443,8080" --scan-types "xss,sqli" --extensions "php,html,txt" --threads 20 --output ./resultados_personalizados
```

## Módulos Individuales

Cada módulo puede ser utilizado de forma independiente para análisis específicos:

### Módulo de Escaneo de Redes

```bash
python3 src/test_network_scanner.py --target 192.168.1.0/24 --ports "1-1000" --output ./resultados_red
```

### Módulo de Análisis de Vulnerabilidades

```bash
python3 src/test_vulnerability_scanner.py --target 192.168.1.10 --ports "22,80,443" --output ./resultados_vuln
```

### Módulo de Escaneo Web de Directorios

```bash
python3 src/test_directory_scanner.py --url https://example.com --wordlist common.txt --extensions "php,html,txt" --output ./resultados_dir
```

### Módulo de Análisis de Vulnerabilidades Web

```bash
python3 src/test_web_vulnerability_scanner.py --url https://example.com --crawl-depth 1 --scan-types "xss,sqli,open_redirect" --output ./resultados_web_vuln
```

## Interpretación de Resultados

### Informes Generados

La herramienta genera varios tipos de informes:

1. **Informes de Texto**: Resúmenes detallados en formato de texto plano.
2. **Informes HTML**: Informes interactivos con gráficos y tablas.
3. **Informes JSON**: Datos estructurados para integración con otras herramientas.
4. **Visualizaciones**: Mapas de red y gráficos estadísticos.

### Estructura de Directorios de Resultados

```
resultados/
├── complete_scan_20250605_121211/
│   ├── network_scan_20250605_121211.json
│   ├── vulnerability_scan_20250605_121211.json
│   ├── directory_scan_20250605_121211.json
│   ├── web_vulnerability_scan_20250605_121211.json
│   ├── network_map_20250605_121211.png
│   ├── charts/
│   │   ├── risk_distribution.png
│   │   └── url_vulnerabilities.png
│   ├── complete_scan_results.json
│   └── complete_scan_report.html
└── cibersecurity_tool.log
```

### Niveles de Riesgo

Las vulnerabilidades se clasifican según su nivel de riesgo:

- **Alto**: Vulnerabilidades críticas que requieren atención inmediata.
- **Medio**: Problemas importantes que deben ser abordados.
- **Bajo**: Cuestiones menores que representan un riesgo limitado.
- **Info**: Información que no representa un riesgo directo pero puede ser útil.

## Mejores Prácticas

1. **Permisos Adecuados**: Ejecutar la herramienta con los permisos necesarios (root/administrador para escaneos completos).
2. **Autorización**: Obtener autorización antes de escanear sistemas que no sean de su propiedad.
3. **Impacto**: Considerar el impacto potencial de los escaneos en sistemas en producción.
4. **Segmentación**: Dividir los escaneos grandes en partes más pequeñas para reducir la carga.
5. **Verificación**: Verificar manualmente los resultados para evitar falsos positivos.
6. **Actualizaciones**: Mantener la herramienta y sus dependencias actualizadas.

## Solución de Problemas

### Problemas Comunes

1. **Error de permisos**: Ejecutar con privilegios elevados (sudo/administrador).
2. **Timeouts en escaneos**: Aumentar los valores de timeout o reducir la concurrencia.
3. **Falsos positivos**: Verificar manualmente los resultados y ajustar la sensibilidad.
4. **Errores de dependencias**: Verificar que todas las dependencias estén instaladas correctamente.

### Logs de Depuración

Para obtener más información sobre errores:

```bash
python3 src/cibersecurity_tool.py --target example.com --log-level DEBUG --output ./debug_results
```

## Limitaciones Conocidas

1. Algunos firewalls pueden bloquear o limitar los escaneos.
2. Los escaneos intensivos pueden generar carga significativa en los sistemas objetivo.
3. La detección de vulnerabilidades se basa en firmas conocidas y puede no detectar vulnerabilidades de día cero.
4. El rendimiento puede variar según la conectividad de red y los recursos del sistema.

## Contribuciones y Desarrollo

### Estructura del Código

Cada módulo sigue una estructura similar:

1. **Clases principales**: Implementan la funcionalidad central.
2. **Clases auxiliares**: Proporcionan funcionalidades de soporte.
3. **Scripts de prueba**: Permiten probar cada módulo de forma independiente.

### Añadir Nuevas Funcionalidades

Para extender la herramienta:

1. Crear un nuevo módulo en `src/modules/` siguiendo la estructura existente.
2. Implementar las interfaces necesarias para la integración.
3. Actualizar el script principal (`cibersecurity_tool.py`) para incluir el nuevo módulo.
4. Añadir pruebas y documentación.

## Licencia y Atribuciones

Esta herramienta se distribuye bajo licencia MIT.

### Herramientas y Bibliotecas Utilizadas

- **Nmap**: Para escaneo de redes (https://nmap.org/)
- **Python-nmap**: Interfaz de Python para Nmap
- **Matplotlib**: Para visualización de datos
- **NetworkX**: Para generación de gráficos de red
- **Requests**: Para comunicación HTTP
- **BeautifulSoup4**: Para análisis HTML
- **Nikto**: Para escaneo de vulnerabilidades web (opcional)
- **OWASP ZAP**: Para análisis avanzado de vulnerabilidades web (opcional)

## Contacto y Soporte

Para soporte técnico o consultas:

- **Email**: soporte@ejemplo.com
- **Sitio web**: https://ejemplo.com/ciberseguridad
- **Repositorio**: https://github.com/usuario/ciberseguridad_proyecto

---

**Nota**: Esta herramienta está diseñada para fines educativos y de seguridad legítima. Utilícela de manera ética y legal, respetando las políticas de seguridad y privacidad aplicables.
