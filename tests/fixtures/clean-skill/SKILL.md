---
name: commit-message-helper
description: Redacta mensajes de commit claros siguiendo Conventional Commits a partir de un diff o de una descripción de cambios. Úsala cuando el usuario pida un mensaje de commit o un resumen de cambios para un repositorio.
---

# Commit message helper

Genera un mensaje de commit a partir de los cambios descritos por el usuario.

## Pasos

1. Lee el diff o la descripción de cambios que aporte el usuario.
2. Elige el tipo (`feat`, `fix`, `docs`, `refactor`, `test`, `chore`).
3. Escribe un resumen de menos de 72 caracteres en imperativo.
4. Añade un cuerpo breve solo si el cambio necesita contexto.

Para contar las líneas de un diff puedes usar `scripts/count_lines.py`.
