#!/usr/bin/env python3
"""
Script de generación de requirements.txt para la herramienta de ciberseguridad.
"""

requirements = [
    "python-nmap>=0.7.1",
    "matplotlib>=3.5.0",
    "networkx>=2.6.3",
    "requests>=2.26.0",
    "beautifulsoup4>=4.10.0",
    "tqdm>=4.62.3",
    "python-owasp-zap-v2.4>=0.0.20"
]

with open("requirements.txt", "w") as f:
    f.write("\n".join(requirements))

print("Archivo requirements.txt generado correctamente.")
