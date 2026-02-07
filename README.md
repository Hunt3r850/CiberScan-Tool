# CiberScan-Tool v2.0 (Actualización 2026)

## Herramienta de Ciberseguridad Automatizada

CiberScan-Tool es una plataforma integral diseñada para automatizar el análisis de seguridad, desde el descubrimiento de redes hasta la detección de vulnerabilidades críticas de última generación.

### 🚀 Novedades de la Versión 2.0 (Febrero 2026)

- **Base de Datos CVE Actualizada**: Integración de vulnerabilidades críticas de 2025 y principios de 2026, incluyendo:
  - **CVE-2025-34026**: Fallo de autenticación en Versa Concerto.
  - **CVE-2025-24813**: RCE en Apache Tomcat.
  - **CVE-2025-40551**: Deserialización en SolarWinds Web Help Desk.
  - **CVE-2025-61882**: RCE en Oracle E-Business Suite.
  - **CVE-2025-55182**: React2Shell RCE (Vulnerabilidad crítica en SSR).
- **Estructura Modular Refactorizada**: Código organizado en paquetes de Python para facilitar la escalabilidad y el mantenimiento.
- **Corrección de Importaciones**: Eliminación de errores de `ModuleNotFoundError` mediante una gestión robusta del `PYTHONPATH`.
- **Instalación Optimizada**: Scripts de configuración mejorados para entornos virtuales.

## 🛠️ Estructura del Proyecto

```
CiberScan-Tool/
├── src/
│   ├── modules/
│   │   ├── network_scanner/      # Escaneo de hosts y puertos
│   │   ├── vulnerability_scanner/# Análisis de CVEs
│   │   ├── web_directory_scanner/# Fuzzing de directorios
│   │   └── web_vulnerability_scanner/ # Análisis de vulnerabilidades web
│   └── cibersecurity_tool.py     # Punto de entrada principal
├── docs/                         # Manuales y documentación técnica
├── tests/                        # Pruebas unitarias y de validación
├── run.sh                        # Script de ejecución rápida
└── setup.py                      # Instalador automatizado
```

## ⚙️ Instalación y Uso

### Requisitos Previos
- Python 3.8+
- Nmap instalado en el sistema

### Instalación Rápida
```bash
git clone https://github.com/Hunt3r850/CiberScan-Tool.git
cd CiberScan-Tool
python3 setup.py
```

### Ejecución
```bash
./run.sh --target 192.168.1.0/24 --scan-type fast --output ./resultados
```

## 🌐 Documentación y Soporte
Visita nuestro portal de documentación: [https://ayjsnvym.manus.space](https://ayjsnvym.manus.space)

---
© 2026 CiberScan-Tool Project. Uso ético y profesional solamente.
