# HUMANS.md — VirusTotal Simple Bulk Scanner

## Qué hace este programa

Escanea archivos en lote contra la API de VirusTotal. Para cada archivo:
1. Consulta VT por su hash SHA256 para ver si ya tiene un análisis previo.
2. Si existe (200), muestra y guarda los resultados.
3. Si no existe (404), sube el archivo a VT para análisis y espera los resultados.
4. Al final, muestra un resumen: maliciosos, sospechosos, no detectados.

## Requisitos

- Python 3.10+
- Una cuenta en [VirusTotal](https://www.virustotal.com) con API key

## Instalación

```bash
pip install requests pytest
```

## Obtener tu API key

1. Crea una cuenta en https://www.virustotal.com
2. Ve a tu perfil: https://www.virustotal.com/gui/my-apikey
3. Copia la API key (64 caracteres)
4. Tu user ID está en la URL de tu perfil: `https://www.virustotal.com/gui/user/{TU_USER_ID}/...`

La primera vez que ejecutes el programa, te pedirá estos datos y los guardará en `vt_api_key.txt`.

## Uso

### Modo CLI

```bash
# Escanear un directorio completo
python vt_bulk.py /ruta/al/directorio

# Filtrar por extensión
python vt_bulk.py -e .exe,.dll /ruta/al/directorio

# Modo silencioso (sin logs detallados)
python vt_bulk.py -q /ruta/al/directorio

# Combinar flags
python vt_bulk.py -e .exe -q /ruta/al/directorio
```

### Modo interactivo (TUI)

Sin argumentos, el programa lanza un asistente paso a paso:

```bash
python vt_bulk.py
```

Te preguntará:
- Directorio a escanear (Enter = directorio actual)
- Extensiones a filtrar (Enter = todas)
- Si quieres guardar resultados en JSON

### Flags disponibles

| Flag | Descripción |
|---|---|
| `-e`, `--extension` | Filtrar por extensiones (ej: `.exe,.dll`) |
| `-q`, `--quiet` | Modo silencioso |
| `-h`, `--help` | Mostrar ayuda |
| `-u`, `--unsafe-only` | *(No implementado)* |
| `-f`, `--full-report` | *(No implementado)* |

## Resultados

Los resultados se guardan automáticamente en `./scans/` como archivos JSON con el formato:
```
{nombre_archivo}-{sha256}.analysis.json
```

Ejemplo: `malware.exe-a1b2c3d4...f5.analysis.json`

## Ejemplo de salida

```
File suspicious.exe retrieved successfully
File clean.txt does not have valid previous analyses, sending to VT

/path/to/suspicious.exe:
  Registered names: ['suspicious.exe', 'test_malware.exe']
  Results: {'malicious': 5, 'suspicious': 1, 'undetected': 60}

/path/to/clean.txt:
  Registered names: ['clean.txt']
  Results: {'malicious': 0, 'suspicious': 0, 'undetected': 70}

Total results:
  Malicious: ['suspicious.exe']
  Suspicious: []
  Undetected: ['clean.txt']
```

## Limitaciones

- Cuota de la API gratuita de VT: 4 requests/minute, 500/day
- Archivos muy grandes pueden tardar en ser analizados por VT
- El programa espera el análisis con un polling cada 2 segundos
- No sube `vt_api_key.txt` al escanear el directorio actual

## Tests

```bash
# Correr todos los tests (41 tests, ~3 segundos)
python -m pytest tests/ -v

# Solo tests unitarios
python -m pytest tests/test_unit.py -v

# Solo tests de integración
python -m pytest tests/test_integration.py -v
```

Todos los tests usan mocks — no se hacen llamadas reales a VirusTotal.
