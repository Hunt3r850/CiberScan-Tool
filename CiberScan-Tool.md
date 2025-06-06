# CiberScan-Tool

<div align="center">
  <img src="https://raw.githubusercontent.com/Hunt3r850/CiberScan-Tool/main/docs/images/logo.png" alt="CiberScan-Tool Logo" width="300"/>
  <br>
  <h3>Herramienta Automatizada de Ciberseguridad</h3>
  <p>Escaneo de redes, análisis de vulnerabilidades y auditoría de seguridad web</p>
</div>

## 📋 Contenido

- [Descripción General](#-descripción-general)
- [Características Principales](#-características-principales)
- [Capturas de Pantalla](#-capturas-de-pantalla)
- [Instalación](#-instalación)
- [Uso Básico](#-uso-básico)
- [Casos de Uso](#-casos-de-uso)
- [Documentación](#-documentación)
- [Contribuciones](#-contribuciones)
- [Roadmap](#-roadmap)
- [Consideraciones Éticas y Legales](#-consideraciones-éticas-y-legales)
- [Agradecimientos](#-agradecimientos)
- [Licencia](#-licencia)

## 🔍 Descripción General

CiberScan-Tool es una herramienta de ciberseguridad automatizada que integra múltiples módulos para realizar análisis completos de seguridad en sistemas y aplicaciones web. Diseñada con una arquitectura modular, permite realizar desde escaneos básicos hasta análisis profundos de vulnerabilidades, adaptándose a diferentes necesidades y escenarios.

## ✨ Características Principales

- **Escaneo de Redes**: Descubrimiento de hosts, puertos abiertos, servicios en ejecución y sistemas operativos.
- **Análisis de Vulnerabilidades**: Detección de vulnerabilidades conocidas en servicios y sistemas.
- **Escaneo Web de Directorios**: Descubrimiento de recursos ocultos en aplicaciones web.
- **Análisis de Vulnerabilidades Web**: Detección de problemas de seguridad como XSS, SQL Injection, Open Redirect y más.
- **Generación Automática de Informes**: Creación de informes detallados en múltiples formatos (texto, HTML, JSON).
- **Visualización de Resultados**: Representación gráfica de la topología de red y estadísticas de vulnerabilidades.
- **Integración con Herramientas Externas**: Compatibilidad con Nikto, OWASP ZAP y otras herramientas de seguridad.

## 📸 Capturas de Pantalla

<div align="center">
  <img src="https://raw.githubusercontent.com/Hunt3r850/CiberScan-Tool/main/docs/images/network_scan.png" alt="Escaneo de Red" width="45%"/>
  <img src="https://raw.githubusercontent.com/Hunt3r850/CiberScan-Tool/main/docs/images/vulnerability_report.png" alt="Informe de Vulnerabilidades" width="45%"/>
  <br><br>
  <img src="https://raw.githubusercontent.com/Hunt3r850/CiberScan-Tool/main/docs/images/directory_scan.png" alt="Escaneo de Directorios" width="45%"/>
  <img src="https://raw.githubusercontent.com/Hunt3r850/CiberScan-Tool/main/docs/images/web_vulnerabilities.png" alt="Vulnerabilidades Web" width="45%"/>
</div>

## 🚀 Instalación

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

## 💻 Uso Básico

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

## 🎯 Casos de Uso

### Auditoría de Seguridad Interna

Ideal para equipos de seguridad que necesitan evaluar periódicamente la postura de seguridad de sus sistemas internos:

```bash
python3 src/cibersecurity_tool.py --target 10.0.0.0/24 --scan-type deep --output ./auditoria_interna
```

### Evaluación de Aplicaciones Web

Perfecto para desarrolladores y equipos de QA que desean verificar la seguridad de sus aplicaciones web antes del despliegue:

```bash
python3 src/cibersecurity_tool.py --web-url https://mi-aplicacion-staging.com --crawl-depth 3 --scan-types "xss,sqli,open_redirect" --output ./evaluacion_web
```

### Análisis Rápido de Vulnerabilidades

Para administradores de sistemas que necesitan verificar rápidamente si un servidor está expuesto a vulnerabilidades conocidas:

```bash
python3 src/cibersecurity_tool.py --target servidor-produccion.com --scan-type fast --output ./analisis_rapido
```

### Descubrimiento de Activos

Útil para mapear todos los activos en una red corporativa y detectar dispositivos no autorizados:

```bash
python3 src/cibersecurity_tool.py --target 192.168.0.0/16 --scan-type normal --ports "21,22,23,25,80,443,8080,8443" --output ./inventario_red
```

## 📚 Documentación

Para más información, consulte:

- [Manual de Usuario](docs/manual_usuario.md): Guía detallada para usuarios finales.
- [Documentación Técnica](docs/documentacion_tecnica.md): Información técnica para desarrolladores y administradores.

## 👥 Contribuciones

¡Las contribuciones son bienvenidas! Si deseas contribuir a este proyecto:

1. Haz un fork del repositorio
2. Crea una rama para tu característica (`git checkout -b feature/nueva-caracteristica`)
3. Realiza tus cambios y haz commit (`git commit -am 'Añadir nueva característica'`)
4. Sube los cambios a tu fork (`git push origin feature/nueva-caracteristica`)
5. Abre un Pull Request

### Áreas para Contribuir

- Mejoras en los algoritmos de detección
- Soporte para nuevas herramientas de seguridad
- Optimizaciones de rendimiento
- Mejoras en la interfaz de usuario
- Traducciones a otros idiomas
- Documentación adicional y ejemplos

## 🗺️ Roadmap

Estas son las características y mejoras planificadas para futuras versiones:

### Versión 1.1
- Interfaz gráfica de usuario (GUI)
- Soporte para escaneo de contenedores Docker
- Integración con bases de datos de vulnerabilidades adicionales

### Versión 1.2
- Análisis de configuraciones de seguridad
- Detección de malware y backdoors
- Soporte para autenticación en aplicaciones web

### Versión 2.0
- Monitorización continua de seguridad
- Análisis de tráfico de red en tiempo real
- Integración con sistemas SIEM
- API REST para integración con otras herramientas

## ⚖️ Consideraciones Éticas y Legales

Esta herramienta está diseñada para fines educativos y de seguridad legítima. El uso indebido de esta herramienta puede violar leyes locales e internacionales. Siempre:

- Obtenga autorización explícita antes de escanear cualquier sistema
- Respete las políticas de seguridad y privacidad aplicables
- Utilice la herramienta de manera responsable y ética
- Reporte vulnerabilidades siguiendo prácticas de divulgación responsable

## 🙏 Agradecimientos

Este proyecto no habría sido posible sin la contribución y el trabajo de:

- La comunidad de código abierto de ciberseguridad
- Los desarrolladores de Nmap, Nikto y OWASP ZAP
- Todos los investigadores de seguridad que documentan y comparten vulnerabilidades
- Las siguientes bibliotecas y proyectos:
  - Python-nmap
  - Requests
  - BeautifulSoup4
  - Matplotlib
  - NetworkX

Un agradecimiento especial a todos los que han probado la herramienta y proporcionado retroalimentación valiosa.

## 📄 Licencia

Este proyecto se distribuye bajo la licencia MIT. Consulte el archivo `LICENSE` para más detalles.
