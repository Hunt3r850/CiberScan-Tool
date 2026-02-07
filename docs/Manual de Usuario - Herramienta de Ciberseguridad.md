# Manual de Usuario - Herramienta de Ciberseguridad

## Introducción

Bienvenido al manual de usuario de la Herramienta de Ciberseguridad Automatizada. Este documento proporciona instrucciones detalladas sobre cómo utilizar la herramienta para realizar análisis de seguridad en sistemas y aplicaciones web.

## Instalación

### Requisitos Previos

Antes de instalar la herramienta, asegúrese de que su sistema cumple con los siguientes requisitos:

- **Sistema Operativo**: Linux (Ubuntu 20.04+), Windows 10+ o macOS 10.15+
- **Python**: Versión 3.8 o superior
- **Espacio en Disco**: Al menos 1GB de espacio libre
- **Memoria RAM**: Mínimo 4GB, recomendado 8GB

### Pasos de Instalación

1. **Descargar el Proyecto**:
   ```bash
   git clone https://github.com/usuario/ciberseguridad_proyecto.git
   cd ciberseguridad_proyecto
   ```

2. **Instalar Dependencias**:
   ```bash
   # Instalar dependencias de Python
   pip3 install -r requirements.txt
   
   # Instalar Nmap (en Ubuntu/Debian)
   sudo apt update
   sudo apt install nmap
   ```

3. **Verificar la Instalación**:
   ```bash
   python3 src/cibersecurity_tool.py --help
   ```

## Primeros Pasos

### Estructura de Directorios

```
ciberseguridad_proyecto/
├── src/               # Código fuente
├── data/              # Datos y diccionarios
├── docs/              # Documentación adicional
└── output/            # Directorio por defecto para resultados
```

### Ejecutar un Primer Escaneo

Para realizar un escaneo básico de su red local:

```bash
python3 src/cibersecurity_tool.py --target 192.168.1.0/24 --scan-type fast --output ./mi_primer_escaneo
```

Este comando realizará:
- Un escaneo rápido de la red 192.168.1.0/24
- Guardará los resultados en el directorio `./mi_primer_escaneo`

## Funcionalidades Principales

### 1. Escaneo de Redes

El módulo de escaneo de redes permite descubrir hosts, puertos abiertos y servicios en una red.

**Ejemplo básico**:
```bash
python3 src/cibersecurity_tool.py --target 192.168.1.0/24 --scan-type normal --ports "22,80,443,8080"
```

**Opciones específicas**:
- `--scan-type`: Tipo de escaneo ('fast', 'normal', 'deep')
- `--ports`: Puertos específicos a escanear

### 2. Análisis de Vulnerabilidades

Este módulo analiza los servicios detectados en busca de vulnerabilidades conocidas.

**Ejemplo**:
```bash
python3 src/cibersecurity_tool.py --target 192.168.1.10 --scan-type deep
```

### 3. Escaneo Web de Directorios

Permite descubrir recursos ocultos en aplicaciones web mediante técnicas de fuerza bruta.

**Ejemplo**:
```bash
python3 src/cibersecurity_tool.py --target example.com --web-url https://example.com --wordlist common.txt --extensions "php,html,bak"
```

**Opciones específicas**:
- `--wordlist`: Diccionario a utilizar
- `--extensions`: Extensiones de archivo a probar
- `--threads`: Número de hilos para escaneo paralelo

### 4. Análisis de Vulnerabilidades Web

Detecta problemas de seguridad comunes en aplicaciones web como XSS, SQL Injection, etc.

**Ejemplo**:
```bash
python3 src/cibersecurity_tool.py --target example.com --web-url https://example.com --crawl-depth 2 --scan-types "xss,sqli,open_redirect"
```

**Opciones específicas**:
- `--crawl-depth`: Profundidad de rastreo
- `--max-urls`: Número máximo de URLs a analizar
- `--scan-types`: Tipos específicos de vulnerabilidades a buscar

## Escenarios de Uso Comunes

### Auditoría de Seguridad Completa

Para realizar una auditoría completa de seguridad:

```bash
python3 src/cibersecurity_tool.py --target example.com --web-url https://example.com --scan-type deep --crawl-depth 2 --max-urls 50 --output ./auditoria_completa
```

### Escaneo Rápido de Vulnerabilidades

Para un escaneo rápido de vulnerabilidades:

```bash
python3 src/cibersecurity_tool.py --target 192.168.1.10 --scan-type fast --output ./escaneo_rapido
```

### Análisis Específico de Aplicación Web

Para analizar una aplicación web específica:

```bash
python3 src/cibersecurity_tool.py --web-url https://example.com/app --crawl-depth 3 --scan-types "xss,sqli,open_redirect,header_injection" --output ./analisis_web
```

## Interpretación de Resultados

### Estructura de los Informes

La herramienta genera varios tipos de informes:

1. **Informe HTML**: Un informe interactivo con gráficos y tablas.
2. **Informe de Texto**: Un resumen detallado en formato de texto plano.
3. **Informe JSON**: Datos estructurados para integración con otras herramientas.

### Niveles de Riesgo

Las vulnerabilidades se clasifican según su nivel de riesgo:

- **Alto (Rojo)**: Vulnerabilidades críticas que requieren atención inmediata.
- **Medio (Naranja)**: Problemas importantes que deben ser abordados.
- **Bajo (Verde)**: Cuestiones menores que representan un riesgo limitado.
- **Info (Azul)**: Información que no representa un riesgo directo.

### Ejemplo de Informe

Un informe típico incluirá:

1. **Resumen Ejecutivo**: Visión general de los hallazgos.
2. **Detalles de Hosts**: Información sobre los hosts escaneados.
3. **Vulnerabilidades Detectadas**: Lista de vulnerabilidades clasificadas por riesgo.
4. **Directorios Web**: Recursos web descubiertos.
5. **Vulnerabilidades Web**: Problemas de seguridad en aplicaciones web.
6. **Recomendaciones**: Sugerencias para mitigar los problemas encontrados.

## Consejos y Mejores Prácticas

### Optimización de Escaneos

1. **Ajustar la Velocidad**: Use `--scan-type fast` para escaneos rápidos o `deep` para análisis exhaustivos.
2. **Limitar el Alcance**: Especifique puertos concretos con `--ports` para escaneos más rápidos.
3. **Paralelismo**: Ajuste `--threads` según los recursos de su sistema.

### Reducción de Falsos Positivos

1. **Verificación Manual**: Siempre verifique manualmente las vulnerabilidades críticas.
2. **Ajustar Sensibilidad**: Use opciones específicas para reducir falsos positivos.
3. **Escaneos Incrementales**: Realice escaneos incrementales para validar resultados.

### Consideraciones Éticas y Legales

1. **Autorización**: Obtenga siempre autorización antes de escanear sistemas.
2. **Impacto**: Considere el impacto potencial de los escaneos en sistemas en producción.
3. **Horarios**: Realice escaneos intensivos en horarios de baja actividad.

## Solución de Problemas

### Problemas Comunes

1. **Error de permisos**:
   - **Síntoma**: "Permission denied" al ejecutar escaneos.
   - **Solución**: Ejecute la herramienta con privilegios elevados (sudo/administrador).

2. **Timeouts en escaneos**:
   - **Síntoma**: Los escaneos se interrumpen o son muy lentos.
   - **Solución**: Aumente los valores de timeout o reduzca la concurrencia.

3. **Falsos positivos**:
   - **Síntoma**: Se reportan vulnerabilidades inexistentes.
   - **Solución**: Verifique manualmente y ajuste la sensibilidad del escaneo.

4. **Errores de dependencias**:
   - **Síntoma**: Errores de importación o módulos no encontrados.
   - **Solución**: Verifique que todas las dependencias estén instaladas correctamente.

### Obtener Ayuda Adicional

Para obtener más información o ayuda:

1. **Logs de Depuración**: Use `--log-level DEBUG` para obtener información detallada.
2. **Documentación**: Consulte el archivo README.md y la documentación en la carpeta docs/.
3. **Soporte**: Contacte con soporte@ejemplo.com para asistencia técnica.

## Glosario de Términos

- **XSS (Cross-Site Scripting)**: Vulnerabilidad que permite inyectar scripts maliciosos en páginas web.
- **SQL Injection**: Vulnerabilidad que permite manipular consultas a bases de datos.
- **Open Redirect**: Vulnerabilidad que permite redirigir a usuarios a sitios maliciosos.
- **CVSS**: Sistema de puntuación para clasificar la gravedad de las vulnerabilidades.
- **Escaneo Pasivo**: Análisis que no interactúa directamente con el objetivo.
- **Escaneo Activo**: Análisis que interactúa directamente con el objetivo para detectar vulnerabilidades.

---

**Nota**: Esta herramienta está diseñada para fines educativos y de seguridad legítima. Utilícela de manera ética y legal, respetando las políticas de seguridad y privacidad aplicables.
