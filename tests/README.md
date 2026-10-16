# Tests · Pruebas

[English](#english) · [Español](#español)

---

## English

```bash
python3 tests/run_tests.py
```

Nothing to install (Python 3.9 or later only).

### Fixtures

| Folder | What it is | Expected result |
|---|---|---|
| `fixtures/clean-skill/` | A harmless example skill | No findings, exit code `0` |
| `fixtures/risky-skill/` | An **artificial** skill containing the patterns the scanner looks for | `NO INSTALAR` (do not install), exit code `2` |

> **The fixtures are inert.** The scripts in `risky-skill` stop on their first line (`exit 0` / `raise SystemExit`), use `.invalid` domains that don't exist, and are never executed: the scanner only reads them. They exist to check that the rules detect what they should.
>
> `mcp.json` is named that way (not `.mcp.json`) so it survives any upload or download that ignores hidden files; the scanner recognizes both names.

### Adding a new case

1. Create a folder under `fixtures/`, or generate the case inside `run_tests.py` with a temporary directory.
2. Add the rule that should fire to the `expected` set in section 2, or add a new section.
3. Run `python3 tests/run_tests.py`.

---

## Español

```bash
python3 tests/run_tests.py
```

No necesita instalar nada (solo Python 3.9 o superior).

### Fixtures

| Carpeta | Qué es | Resultado esperado |
|---|---|---|
| `fixtures/clean-skill/` | Una skill inofensiva de ejemplo | Sin hallazgos, código de salida `0` |
| `fixtures/risky-skill/` | Una skill **artificial** con los patrones que busca el escáner | `NO INSTALAR`, código de salida `2` |

> **Los fixtures son inertes.** Los scripts de `risky-skill` terminan en la primera línea (`exit 0` / `raise SystemExit`), usan dominios `.invalid` que no existen y nunca se ejecutan: el escáner solo los lee. Están ahí para comprobar que las reglas detectan lo que deben.
>
> `mcp.json` se llama así (y no `.mcp.json`) para que sobreviva a cualquier subida o descarga que ignore archivos ocultos; el escáner reconoce ambos nombres.

### Añadir un caso nuevo

1. Crea una carpeta en `fixtures/` o genera el caso dentro de `run_tests.py` con un directorio temporal.
2. Añade la regla que debe saltar al conjunto `expected` de la sección 2, o una sección nueva.
3. Ejecuta `python3 tests/run_tests.py`.
