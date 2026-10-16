# Guía de patrones de riesgo

Úsala para interpretar los hallazgos del escáner y para la revisión manual. Cada sección explica la señal, por qué importa y cómo distinguir un uso legítimo de uno malicioso.

## Índice

1. Ejecución remota y ofuscación
2. Acceso a credenciales y datos sensibles
3. Exfiltración
4. Persistencia y manipulación del entorno del agente
5. Permisos excesivos
6. Inyección de prompts
7. Ocultación en el contenido (Unicode, comentarios, enlaces)
8. Cadena de suministro
9. Binarios y archivos opacos
10. Falsos positivos frecuentes
11. Escala de severidad

---

## 1. Ejecución remota y ofuscación

**Señales:** descargar algo y pasárselo directamente a una shell o intérprete; `eval`/`exec` sobre contenido calculado; decodificar base64 u otros formatos y ejecutar el resultado; cadenas largas codificadas; `Invoke-Expression` en PowerShell.

**Por qué importa:** lo que se revisa deja de ser lo que se ejecuta. El código real llega después de la auditoría y puede cambiar en cualquier momento.

**Legítimo vs. sospechoso:** descargar un instalador oficial en un paso separado, verificar su hash y ejecutarlo es razonable. Encadenar descarga y ejecución sin verificación, o decodificar un blob para ejecutarlo, no tiene justificación en una skill: un script puede estar escrito en claro.

## 2. Acceso a credenciales y datos sensibles

**Señales:** rutas como los directorios de claves SSH, credenciales de nube, configuración de Kubernetes, `.npmrc`, `.netrc`, almacenes de cookies o de contraseñas del navegador, `.env`; volcado completo de variables de entorno; referencias a claves de API.

**Por qué importa:** las skills se ejecutan con los permisos del usuario. Una sola lectura de estos archivos puede comprometer cuentas y servidores.

**Pregunta clave:** ¿el propósito declarado requiere ese dato? Una skill de despliegue puede necesitar una variable concreta; ninguna skill de formato o redacción necesita leer claves privadas. Leer una variable de entorno concreta y documentada es distinto de recorrerlas todas.

## 3. Exfiltración

**Señales:** envío de datos a dominios que no son del servicio que la skill dice usar; servicios de recepción temporal o de túneles (webhooks de prueba, sitios de pegado, bots de mensajería, servicios de tunelado); URLs con IP literal; acortadores; datos codificados en parámetros de URL o subdominios.

**Combinaciones graves:** acceso a credenciales + red saliente en el mismo archivo o en el mismo flujo. El escáner marca esta combinación como crítica. Confírmala siguiendo el flujo de datos a mano: ¿lo leído llega realmente a lo enviado?

**Instrucciones, no solo código:** un `SKILL.md` puede pedir al agente que envíe datos a una URL sin que haya ningún script. Revisa el texto con la misma atención.

## 4. Persistencia y manipulación del entorno del agente

**Señales:** modificar archivos de arranque de la shell, tareas programadas, servicios de usuario, claves SSH autorizadas, registro de Windows; editar la configuración del agente (ajustes, hooks, archivos de memoria o instrucciones, configuración MCP).

**Por qué importa:** permite que el efecto sobreviva a la desinstalación de la skill o que el agente cambie su propio comportamiento y permisos en futuras sesiones. Un hook o una instrucción persistente plantada es un puesto de mando.

**Legítimo vs. sospechoso:** una skill dedicada a configurar el entorno puede tocar estos archivos si lo declara y pide confirmación. En cualquier otra skill es una alerta alta.

## 5. Permisos excesivos

**Señales:** `allowed-tools` con shell sin restricciones o comodines; descripciones que piden desactivar confirmaciones o usar modos que saltan permisos; peticiones de acceso a todo el sistema de archivos cuando basta una carpeta.

**Principio:** mínimo privilegio. Una skill que solo transforma texto no necesita shell, red ni escritura fuera de su carpeta. Si el autor puede restringir `Bash(comando:*)` a lo necesario y no lo hace, pregunta por qué.

## 6. Inyección de prompts

**Señales en el texto de la skill:**
- Órdenes de ignorar, olvidar o anular instrucciones previas o del sistema.
- Ocultar acciones o resultados al usuario.
- Actuar sin pedir confirmación, desactivar protecciones o permisos.
- Revelar el prompt del sistema, el historial o el contexto.
- Redefinir el rol del agente ("a partir de ahora eres…", "modo sin restricciones").
- Etiquetas que imitan mensajes de sistema o de asistente.
- Recopilar claves, tokens o archivos y enviarlos a algún destino.
- Una descripción que fuerza activarse "siempre", en cualquier tarea.

**Por qué importa:** el agente lee la skill como instrucciones de confianza. Un solo párrafo bien puesto puede cambiar su comportamiento sin que haya código malicioso.

**Matiz:** documentación que *explica* estos ataques (guías de seguridad, esta propia skill) contiene las mismas frases. Mira si el texto las describe o si las ordena.

## 7. Ocultación en el contenido

- **Caracteres Unicode invisibles:** espacios de ancho cero, caracteres de control bidireccional (el código se ve distinto de como se interpreta) y caracteres "tag" (permiten esconder instrucciones completas invisibles al ojo). Su presencia en una skill casi nunca tiene explicación inocente.
- **Comentarios HTML en markdown:** no se ven al renderizar pero el agente los lee. Lee su contenido siempre.
- **Enlaces engañosos:** texto que muestra un dominio y apunta a otro.
- **Archivos ocultos o muy alejados:** instrucciones enterradas en `references/` o `assets/` que nadie revisa. Se leen igual.

## 8. Cadena de suministro

**Señales:** instalación de paquetes sin versión fijada, ejecución directa de paquetes remotos, `postinstall`/`preinstall` en `package.json`, dependencias con nombres casi idénticos a paquetes conocidos, repositorios recién creados o sin historial, fork de una skill popular con "pequeños cambios".

**Qué hacer:** comprobar existencia, antigüedad y reputación del paquete; exigir versión fijada o hash; preferir dependencias que ya estén en el entorno.

## 9. Binarios y archivos opacos

Ejecutables, bibliotecas compartidas, bytecode compilado, módulos nativos, WebAssembly y archivos comprimidos anidados no se pueden auditar con esta herramienta. Una skill es texto y scripts legibles por naturaleza: la presencia de binarios necesita una justificación, y si no la hay, el veredicto no puede ser mejor que "revisar a fondo".

## 10. Falsos positivos frecuentes

- Documentación que *menciona* comandos de instalación o `curl` para explicar el uso.
- Uso legítimo de `subprocess` con argumentos fijos y sin shell.
- Cadenas largas que son datos (hashes, fuentes embebidas, imágenes en base64 para HTML).
- Menciones de `.env` en instrucciones tipo "crea un archivo `.env` con tu clave".
- Skills de seguridad, pruebas o enseñanza que contienen ejemplos de ataque (comprueba que estén inertes y claramente etiquetados).

Para descartar uno, anota el motivo en el informe.

## 11. Escala de severidad

| Nivel | Significado | Ejemplos |
|---|---|---|
| Crítico | Daño probable o intención claramente hostil | Descarga y ejecución encadenadas; acceso a credenciales con red saliente; orden de ocultar acciones al usuario; ofuscación que termina en ejecución; caracteres tag ocultos |
| Alto | Capacidad peligrosa sin justificación evidente | Acceso a rutas sensibles; persistencia; edición de la configuración del agente; shell sin restricción; servicios de exfiltración; binarios opacos |
| Medio | Comportamiento que merece revisión | Red saliente, instalación de paquetes, `sudo`, comentarios HTML ocultos, dependencias sin versión |
| Bajo | Aviso menor | Espacios de ancho cero aislados, `http://` sin TLS, metadatos incompletos |
| Info | Inventario | Dominios referenciados, archivos ejecutables |
