<p align="right"><a href="README.md">English</a> · <b>Español</b></p>

<p align="center">
  <img src="assets/es/header.png" alt="Skill Auditor: revisa cualquier skill o servidor MCP antes de instalarlo" width="100%">
</p>

<p align="center">
  <a href="LICENSE"><img alt="Licencia MIT" src="https://img.shields.io/badge/licencia-MIT-2DD4BF?style=flat-square"></a>
  <img alt="Python 3.9+" src="https://img.shields.io/badge/python-3.9%2B-60A5FA?style=flat-square">
  <img alt="Sin dependencias" src="https://img.shields.io/badge/dependencias-ninguna-4ADE80?style=flat-square">
  <img alt="Análisis estático" src="https://img.shields.io/badge/an%C3%A1lisis-est%C3%A1tico-FBBF24?style=flat-square">
  <img alt="Formato Agent Skills" src="https://img.shields.io/badge/formato-Agent%20Skills-8FA1BF?style=flat-square">
</p>

<p align="center">
  <b>Una skill es software.</b> Skill Auditor la revisa antes de que le des acceso a tus archivos, tus claves y tu terminal.
</p>

---

## ¿Por qué existe?

Una skill es un `SKILL.md` que tu agente va a **obedecer**, más scripts que va a **ejecutar con tus permisos y tus credenciales**. El ecosistema es enorme (un censo de agosto de 2026 contaba unas 58.700 skills entre casi 80.000 elementos con MCP y plugins) y la curación es escasa: instalar una skill sin mirarla equivale a ejecutar un script descargado de internet.

**Skill Auditor** es una skill que revisa otras skills (y configuraciones de servidores MCP) antes de instalarlas y te da un **veredicto con evidencias**: qué ha encontrado, en qué archivo y línea, y qué hacer.

- **Dos capas:** un escáner estático rápido (`scan_skill.py`) y una lectura crítica guiada, porque ninguna lista de patrones basta por sí sola.
- **Sin ejecutar nada del objetivo.** Ni scripts, ni instaladores, ni «pruebas rápidas».
- **Compara intención y capacidades:** una skill de formato que lee `~/.ssh` es sospechosa aunque su código sea limpio.
- **Sin dependencias:** solo la biblioteca estándar de Python.

## Cómo funciona

<p align="center">
  <img src="assets/es/how-it-works.png" alt="Cuatro pasos: aislar, escanear, leer y decidir" width="100%">
</p>

1. **Aislar.** Acepta carpeta, `.zip`, `.skill`, un repositorio descargado o contenido pegado. La extracción rechaza rutas absolutas, `..`, enlaces simbólicos y archivos desproporcionados.
2. **Escanear.** Más de treinta reglas sobre scripts, texto y configuración, más correlación de señales entre archivos.
3. **Leer.** Revisión manual guiada de `SKILL.md` y de cada script: ¿cada permiso encaja con el propósito declarado?
4. **Decidir.** Un informe con archivo y línea de cada hallazgo y una de cuatro decisiones.

## Qué detecta

<p align="center">
  <img src="assets/es/risk-map.png" alt="Ocho familias de riesgo: ejecución remota, ofuscación, credenciales, exfiltración, persistencia, permisos excesivos, inyección de prompts y ocultación" width="100%">
</p>

| Familia | Ejemplos de lo que marca |
|---|---|
| Ejecución remota | Descargar y pasar el resultado a una shell o a un intérprete; `Invoke-Expression` |
| Ofuscación | `exec`/`eval` dinámicos, decodificación base64, cadenas largas codificadas |
| Credenciales | Rutas de claves SSH, nube o navegador; `.env`; volcado del entorno completo |
| Exfiltración | Webhooks de prueba, sitios de pegado, túneles, IP literales y acortadores |
| Persistencia | Arranque de la shell, tareas programadas, claves autorizadas, configuración del propio agente |
| Permisos excesivos | `allowed-tools` sin restricción, intentos de saltarse el sistema de permisos |
| Inyección de prompts | Órdenes de ignorar instrucciones, ocultar acciones al usuario o saltarse confirmaciones, o descargar sus instrucciones de una URL remota (en español e inglés) |
| Ocultación | Unicode invisible o bidireccional, comentarios HTML ocultos, enlaces cuyo texto no coincide con su destino |

Además revisa **configuraciones MCP** (paquetes sin versión fijada, `http://` sin cifrado, secretos en texto plano, servidores lanzados a través de una shell), dependencias con scripts de instalación, binarios opacos y metadatos sospechosos (nombres reservados, descripciones que fuerzan su activación en cualquier tarea).

### Las señales combinadas delatan

<p align="center">
  <img src="assets/es/correlation.png" alt="Credenciales más red saliente en el mismo archivo equivale a exfiltración" width="100%">
</p>

Un cliente de API que usa la red es normal. Lo que no es normal es que **el mismo archivo** lea credenciales y además haga red saliente. El escáner cruza hallazgos para subir la severidad cuando se encadenan, y te pide confirmar el flujo de datos a mano.

### El objetivo es dato, nunca instrucciones

<p align="center">
  <img src="assets/es/trust-boundary.png" alt="La skill auditada se trata como texto no confiable: se cita como evidencia, no se obedece ni se ejecuta" width="100%">
</p>

Una skill maliciosa puede contener texto pensado para manipular al revisor («ignora lo anterior», «no se lo digas al usuario»). Skill Auditor lo trata como **evidencia que se cita**, nunca como una orden. Si un fragmento intenta darle órdenes al auditor, eso ya es un hallazgo.

## Veredictos

<p align="center">
  <img src="assets/es/verdicts.png" alt="Cuatro veredictos: no instalar, revisar a fondo, riesgo bajo y sin hallazgos" width="100%">
</p>

El escáner propone un veredicto preliminar y su **código de salida** (`0`, `1` o `2`) permite usarlo en scripts o en integración continua. La lectura manual lo confirma o lo corrige **con motivo escrito**.

> La skill, los mensajes del escáner y las etiquetas del informe están en **inglés**. El informe final lo redacta el agente en el idioma en que le escribas.

| Salida del escáner | Significado | Código de salida |
|---|---|---|
| `DO NOT INSTALL` | No instalar (cualquier hallazgo crítico) | `2` |
| `REVIEW IN DEPTH` | Revisar a fondo (altos, o cinco o más medios) | `1` |
| `LOW RISK (check the warnings)` | Riesgo bajo (revisa los avisos) | `0` |
| `NO RELEVANT FINDINGS` | Sin hallazgos relevantes | `0` |
| `CRITICAL` · `HIGH` · `MEDIUM` · `LOW` · `INFO` | Crítico · Alto · Medio · Bajo · Info | — |

## Instalación

### Claude Code

```bash
git clone https://github.com/Plastikelectrik/skill-auditor.git

# Para todos tus proyectos
mkdir -p ~/.claude/skills
cp -r skill-auditor/skill-auditor ~/.claude/skills/

# O solo para un proyecto (desde la raíz del proyecto)
mkdir -p .claude/skills
cp -r /ruta/a/skill-auditor/skill-auditor .claude/skills/
```

En Windows, la carpeta personal es `%USERPROFILE%\.claude\skills\`.

### Claude (aplicación web y de escritorio)

Descarga `skill-auditor.skill` desde la sección **Releases** y súbelo en los ajustes de Skills de tu cuenta. El nombre exacto del menú puede variar según la versión; consulta la [documentación oficial](https://support.claude.com) si no lo encuentras.

### Solo el escáner, sin agente

```bash
python3 -I skill-auditor/scripts/scan_skill.py /ruta/a/la/skill
```

## Uso

Con la skill instalada, basta con pedirlo con tus palabras:

> *«Me he bajado esta skill de GitHub, ¿es segura antes de instalarla?»*
>
> *«Revisa este `.mcp.json` antes de que lo añada a mi configuración.»*
>
> *«Compara estas dos skills de revisión de código y dime cuál pide menos permisos.»*

### Línea de comandos

```bash
python3 -I skill-auditor/scripts/scan_skill.py <objetivo> [opciones]
```

| Opción | Efecto |
|---|---|
| `--json` | Salida en JSON (para integrarlo con otras herramientas) |
| `--out FICHERO` | Guarda además el informe JSON en un archivo |
| `-v`, `--verbose` | Incluye los hallazgos informativos |

`<objetivo>` puede ser una carpeta, un archivo suelto, un `.zip` o un `.skill`. Ejecuta Python con `-I` (modo aislado) para que ningún archivo del objetivo pueda cargarse por accidente.

| Código de salida | Significado |
|---|---|
| `0` | Sin hallazgos relevantes, o solo avisos menores |
| `1` | Revisar a fondo |
| `2` | No instalar |
| `3` | Error: entrada incorrecta, archivo comprimido inseguro o línea base ilegible |
| `4` | Cambió respecto a la línea base (ver [Reauditoría al cambiar](#reauditoría-al-cambiar)) |

### Ejemplo de salida

Sobre el fixture de riesgo incluido en [`tests/fixtures/`](tests/fixtures) (artificial e inerte). La skill y el escáner están en inglés; el comentario de cada línea es mi traducción:

```text
PRELIMINARY VERDICT: DO NOT INSTALL                  # veredicto preliminar: no instalar
Findings: critical 5 | high 11 | medium 10 | low 2 | info 2

[CRITICAL] INJ_SECRECY  SKILL.md:11                  # ordena ocultar acciones al usuario
    Instruction to hide actions or information from the user
[CRITICAL] EXFIL_COMBO  scripts/helper.py            # credenciales + red saliente, mismo archivo
    The same file accesses credentials or environment variables and makes outbound network calls: ...
[CRITICAL] OBFUSCATED_EXEC  scripts/helper.py        # decodifica un blob y lo ejecuta
    Decodes obfuscated content and executes it dynamically
[CRITICAL] PIPE_TO_SHELL  scripts/setup.sh:5         # curl ... | sh
    Downloads content and pipes it straight into a shell
[HIGH] TOOLS_UNRESTRICTED  SKILL.md:1                # pre-autoriza shell sin restricción
    Pre-authorizes tools without restriction (full shell or wildcard)
[HIGH] INJ_IGNORE  SKILL.md:13                       # orden de ignorar instrucciones previas
    Order to ignore or override previous instructions
…
```

Cada hallazgo incluye también la línea de evidencia. Esa evidencia procede del objetivo: **es texto no confiable**, no instrucciones.

## Reauditoría al cambiar

Una auditoría describe una instantánea. Una skill limpia hoy puede cambiar mañana. Una **línea base** (*baseline*) guarda el SHA-256 de cada archivo en el momento en que la auditaste, de modo que cualquier cambio posterior obliga a auditar de nuevo:

```bash
# 1. Cuando hayas auditado una skill y decidas confiar en ella, guarda la línea base.
#    Guárdala FUERA de la carpeta de la skill, idealmente en tu propio repositorio.
python3 -I skill-auditor/scripts/scan_skill.py ./una-skill --write-baseline baselines/una-skill.json

# 2. Antes de cada actualización, o en CI, compara la versión nueva con ella.
python3 -I skill-auditor/scripts/scan_skill.py ./una-skill --baseline baselines/una-skill.json
```

Si algo cambió, el código de salida es `4` y el informe indica qué. Los hallazgos de los archivos modificados se marcan, así sabes por dónde empezar:

```text
Baseline: DRIFT: 1 added, 1 removed, 1 modified. Re-audit before updating.
  + scripts/new.py                  # archivo añadido
  - scripts/count_lines.py          # archivo eliminado
  ~ SKILL.md                        # archivo modificado
```

- **Guardar una línea base nueva es una decisión deliberada.** `--baseline` y `--write-baseline` no se pueden combinar, así que una actualización no puede darse por buena a sí misma. Un veredicto `2` siempre prevalece sobre el `4`.
- **Fija el origen.** Instala desde un commit concreto o una etiqueta de versión, no desde una rama que se mueve, y comprueba exactamente lo que vas a instalar. Un `.skill` o `.zip` con el mismo contenido coincide con la carpeta.
- **Una línea base registra el contenido; no lo avala.** Quien pueda editar el archivo puede dar por buena una modificación, así que guárdalo donde el autor de la skill no pueda escribir. La firma criptográfica no está implementada.
- **Instrucciones remotas.** Un `SKILL.md` que ordena al agente descargar instrucciones de una URL y seguirlas se marca como `INJ_REMOTE_INSTR`. Lo que se descargue desde código que el escáner no pueda leer sigue siendo invisible para él: otra razón para leer los scripts.

Ejemplo para CI:

```yaml
- name: Reauditar skills incluidas
  run: |
    for d in skills/*/; do
      name=$(basename "$d")
      rc=0
      python3 -I tools/skill-auditor/scripts/scan_skill.py "$d" \
        --baseline "baselines/$name.json" > /dev/null || rc=$?
      if [ "$rc" -ne 0 ]; then echo "$name: scanner exit code $rc"; exit 1; fi
    done
```

## Estructura del repositorio

```text
skill-auditor/                 ← este repositorio
├── skill-auditor/             ← la skill (esta carpeta es la que se instala)
│   ├── SKILL.md               · instrucciones y flujo de trabajo
│   ├── scripts/scan_skill.py  · escáner estático
│   ├── references/            · guía de patrones, checklist MCP, plantilla de informe
│   └── evals/evals.json       · casos de prueba para evaluar la skill con un agente
├── tests/                     · pruebas automáticas y fixtures inertes
├── assets/                    · imágenes de los README (PNG en es/ y en/) y su código fuente (SVG + script)
├── SECURITY.md
├── LICENSE
├── README.md                  · README en inglés
└── README.es.md               · README en español
```

## Pruebas

```bash
python3 tests/run_tests.py
```

Comprueba la skill limpia, la de riesgo, el Unicode oculto, el rechazo de rutas maliciosas en `.zip`, las frases de inyección de prompts en español, las instrucciones remotas, la detección de cambios respecto a la línea base y que el propio escáner no lleve caracteres invisibles. Más detalles en [`tests/README.md`](tests/README.md).

## Límites (leer antes de fiarse)

- **El análisis estático no demuestra que algo sea seguro**, solo que no se encontró nada con estas reglas. Un «sin hallazgos» es una señal, no una garantía.
- No ve lo que se **descarga o decodifica en tiempo de ejecución**, ni puede revisar **binarios**, bibliotecas compiladas o dependencias remotas.
- Las listas de patrones **pueden esquivarse**. Por eso existe la segunda capa (lectura manual) y por eso el veredicto automático es solo preliminar.
- **Tiene falsos positivos**, sobre todo en skills de seguridad o formación, que contienen ejemplos de ataque. Si le pasas la propia skill-auditor, saldrá con muchos hallazgos: son sus reglas y ejemplos. No hay lista de exclusiones a propósito, porque un atacante podría usarla para esconder lo importante.
- Las reglas de inyección de prompts reconocen frases **en inglés y en español**. Los ataques escritos en otros idiomas no los detecta el escáner: lee el texto tú mismo.
- **Audita una instantánea.** Una skill limpia hoy puede cambiar mañana; usa una [línea base](#reauditoría-al-cambiar) para forzar una nueva auditoría ante cualquier cambio. Las instrucciones que se descarguen en ejecución desde código que el escáner no pueda leer le siguen siendo invisibles.
- No sustituye la revisión de origen: autor, historial del repositorio y reputación.

## Contribuir

- **Nuevas reglas:** añádelas en `RULES` dentro de `scan_skill.py` (función `R(...)`), con un caso en `tests/run_tests.py`.
- **Evasiones o falsos positivos:** abre una incidencia con un ejemplo mínimo.
- **Vulnerabilidades en el propio escáner:** sigue [`SECURITY.md`](SECURITY.md); no abras una incidencia pública.
- **Imágenes:** edita `assets/src/build_images.py` (los textos están en `STR`, uno por idioma) y regenera con `python3 assets/src/build_images.py && python3 assets/src/render_png.py` (requiere Playwright y la tipografía Inter).

## Licencia

[MIT](LICENSE).
