#!/bin/bash
# Script para ejecutar la herramienta desde el entorno virtual
if [ -d "venv" ]; then
    source venv/bin/activate
fi
export PYTHONPATH=$PYTHONPATH:$(pwd)
python3 src/cibersecurity_tool.py "$@"
