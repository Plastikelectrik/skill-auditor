# Security policy · Política de seguridad

[English](#english) · [Español](#español)

---

## English

### What this tool is and isn't

Skill Auditor is a **first-pass static analysis filter**. It reduces the risk of installing a third-party skill or MCP server, but it **does not prove anything is safe**: only that nothing was found with these rules. It does not execute the audited code, so it cannot see what is downloaded or decoded at runtime, nor review binaries or remote dependencies.

### Reporting a vulnerability in this tool

If you find a flaw in the scanner itself (for example, a way for a malicious file to cause code execution when analyzed, a path traversal when extracting a `.zip`, or an easy rule evasion):

1. **Do not open a public issue** with exploitation details.
2. Use **Security → Report a vulnerability** on the repository (GitHub private advisories).
3. Include a minimal skill or file that reproduces the problem, and the scanner version.

### Rule evasions

Any pattern list can be bypassed. If you find an evasion that cannot be exploited against the scanner itself, it is welcome as a regular issue or as a pull request with a new case in `tests/`.

### Relevant design decisions

- The scanner **never executes, imports or evaluates** anything from the target; it only reads bytes and text.
- `.zip`/`.skill` extraction rejects absolute paths, `..`, symlinks and oversized archives.
- There is **deliberately no ignore list**: an attacker could use it to hide what matters.
- The output includes text from the target; treat it as **untrusted data**, never as instructions.
- Baseline files (`--baseline`) are untrusted input too: they are parsed as plain JSON, validated and size-limited, never evaluated. A baseline records content, it does not endorse it, and whoever can edit it can re-bless a change.

---

## Español

### Qué es y qué no es esta herramienta

Skill Auditor es un **primer filtro de análisis estático**. Reduce el riesgo de instalar una skill o un servidor MCP de terceros, pero **no demuestra que algo sea seguro**: solo que no se encontró nada con estas reglas. No ejecuta el código auditado, por lo que no puede ver lo que se descarga o se decodifica en tiempo de ejecución, ni revisar binarios o dependencias remotas.

### Cómo informar de una vulnerabilidad en esta herramienta

Si encuentras un fallo en el propio escáner (por ejemplo, una forma de que un archivo malicioso provoque la ejecución de código al ser analizado, un desbordamiento de ruta al extraer un `.zip`, o una evasión sencilla de una regla):

1. **No abras una incidencia pública** con los detalles de explotación.
2. Usa el apartado **Security → Report a vulnerability** del repositorio (avisos privados de GitHub).
3. Incluye una skill o archivo mínimo que reproduzca el problema y la versión del escáner.

### Evasiones de reglas

Cualquier lista de patrones puede esquivarse. Si encuentras una evasión que no sea explotable contra el propio escáner, es bienvenida como incidencia normal o como *pull request* con un caso nuevo en `tests/`.

### Decisiones de diseño relevantes

- El escáner **nunca ejecuta, importa ni evalúa** nada del objetivo; solo lee bytes y texto.
- La extracción de `.zip`/`.skill` rechaza rutas absolutas, `..`, enlaces simbólicos y archivos desproporcionados.
- **No existe lista de exclusiones** (`ignore`) a propósito: un atacante podría usarla para ocultar lo importante.
- La salida incluye texto del objetivo; debe tratarse como **dato no confiable**, nunca como instrucciones.
- Los archivos de línea base (`--baseline`) también son entrada no confiable: se leen como JSON simple, se validan y tienen límite de tamaño, y nunca se evalúan. Una línea base registra contenido, no lo avala, y quien pueda editarla puede dar por buena una modificación.
