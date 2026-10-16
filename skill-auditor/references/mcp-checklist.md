# Lista de comprobación para servidores MCP

Un servidor MCP es un programa que se ejecuta en la máquina del usuario (local) o un servicio al que se le envían datos (remoto). Instalarlo equivale a darle un permiso permanente. Revisa cada punto antes de recomendar su uso.

## 1. Origen y reputación

- ¿Quién lo publica? ¿Es el propio proveedor del servicio o un tercero?
- ¿El repositorio tiene historial, mantenimiento y revisión de código, o es reciente y sin actividad?
- ¿El nombre se parece a otro más conocido? (typosquatting)

## 2. Qué se ejecuta (servidores locales)

- **Comando:** `npx`, `uvx`, `bunx`, `pipx` o `docker` descargan y ejecutan código remoto en cada arranque. Comprueba que el paquete tenga **versión fijada** (`paquete@1.2.3`) y que sea el esperado.
- Una bandera como `-y` acepta la instalación sin preguntar: aceptable solo con versión fijada y origen conocido.
- **Shell:** comandos que lanzan `sh -c`, `bash -c`, `cmd /c` o `powershell -Command` con cadenas largas son una alerta alta.
- **Rutas:** ¿ejecuta un binario local que no puedes inspeccionar?
- **Docker:** revisa montajes de volúmenes (¿monta el directorio personal entero?), modo privilegiado y red de host.

## 3. Conexión remota

- La URL debe usar **HTTPS**. `http://` expone datos y credenciales.
- Dominio coherente con el proveedor. Desconfía de IP literales, acortadores y túneles temporales.
- ¿Qué datos se envían al servidor en cada llamada? ¿Hay política de privacidad y de retención?
- ¿La autenticación usa OAuth con alcances limitados o una clave de larga duración?

## 4. Credenciales y variables de entorno

- No pongas secretos en texto plano dentro del archivo de configuración si este se versiona.
- Pasa solo las variables que el servidor necesita; no heredes todo el entorno.
- Usa credenciales con el mínimo alcance y revocables (solo lectura si basta).

## 5. Alcance de las herramientas

- Lista las herramientas que expone. ¿Incluyen escritura, borrado, envío de mensajes, pagos o ejecución de comandos?
- Las herramientas con efectos irreversibles deben requerir confirmación humana.
- Una herramienta cuyo nombre o descripción no coincide con lo que hace es un indicio de manipulación: lee las descripciones completas, porque también las lee el agente y pueden contener instrucciones ocultas.

## 6. Combinaciones peligrosas

Pocos permisos son graves por separado, pero lo son juntos:

- Acceso a archivos locales + herramienta de red o de envío de mensajes.
- Lectura de correo o documentos privados + navegación web o ejecución de código.
- Herramienta que ingiere contenido externo no confiable (webs, correos, issues) + herramientas con efectos (esta combinación permite inyección de prompts indirecta).

Si se da alguna, recomienda separar servidores, limitar alcances o exigir confirmación en cada acción.

## 7. Resultado

Anota en el informe: comando exacto y versión, dominios, variables de entorno, herramientas expuestas y qué restricciones recomiendas (versión fija, alcance mínimo, confirmación manual, sandbox).
