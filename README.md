# CiberScan-Tool v2.0

CiberScan-Tool integra descubrimiento de red, correlacion de servicios con CVE,
descubrimiento de rutas web y comprobaciones activas de seguridad web. Los
resultados se pueden exportar a JSON y a informes legibles en HTML o texto.

> Utiliza esta herramienta unicamente sobre sistemas propios o para los que
> tengas autorizacion explicita. Los escaneos generan trafico activo.

## Funciones

- Descubrimiento de hosts, puertos, servicios y sistemas operativos con Nmap.
- Consulta de una base CVE local y, opcionalmente, de la API de Vulners.
- Descubrimiento concurrente de rutas a partir de diccionarios.
- Pruebas de XSS reflejado, inyeccion SQL basada en errores, redireccion abierta
  e inyeccion de cabeceras.
- Rastreo limitado al mismo host y con profundidad y cantidad configurables.
- Informes TXT, HTML y JSON para los modulos de seguridad.

## Requisitos

- Python 3.8 o posterior.
- Nmap instalado y disponible en `PATH` para los escaneos de red.

En Amazon Linux/Fedora/RHEL puedes instalar Nmap con `sudo dnf install nmap`.
En otros sistemas, consulta el gestor de paquetes de tu distribucion.

## Instalacion

```bash
git clone https://github.com/Hunt3r850/CiberScan-Tool.git
cd CiberScan-Tool
python3 -m venv venv
venv/bin/python -m pip install --upgrade pip
venv/bin/python -m pip install -r requirements.txt
```

El instalador interactivo heredado sigue disponible con `python3 setup.py`,
pero el procedimiento anterior es mas apropiado para automatizacion.

## Uso

```bash
./run.sh --target 192.168.1.0/24 --scan-type fast --output ./output
```

Opciones utiles:

```text
--ports 22,80,443
--web-url https://aplicacion.example
--wordlist /ruta/diccionario.txt
--extensions php,html,bak
--crawl-depth 2
--max-urls 25
--scan-types xss,sqli,open_redirect,header_injection
```

El script `run.sh` se puede invocar desde cualquier directorio y utiliza
automaticamente `venv/` cuando existe.

## Estructura

```text
src/
├── cibersecurity_tool.py
└── modules/
    ├── network_scanner/
    ├── vulnerability_scanner/
    ├── web_directory_scanner/
    └── web_vulnerability_scanner/
data/
docs/
tests/
```

## Validacion

Las pruebas no realizan escaneos reales; sustituyen las llamadas de red por
respuestas controladas.

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_validation*.py'
```

## Documentacion

La documentacion tecnica y los manuales historicos estan en [`docs/`](docs/).
