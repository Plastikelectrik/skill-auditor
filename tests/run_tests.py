#!/usr/bin/env python3
"""Pruebas del escáner de Skill Auditor. Sin dependencias: solo la biblioteca estándar.

Uso:
    python3 tests/run_tests.py

Qué comprueba:
  1. La skill limpia sale sin hallazgos (código 0).
  2. La skill de riesgo sale NO INSTALAR (código 2) y se detectan las reglas esperadas.
  3. Los caracteres Unicode ocultos reales se detectan.
  4. Un .zip con una ruta `../` se rechaza y no escribe fuera de su carpeta.
  5. Un .skill legítimo se analiza igual que su carpeta.
  6. El propio código fuente del escáner no contiene caracteres invisibles.

Los fixtures de tests/fixtures son INERTES: nunca se ejecutan, solo se leen.
"""
import json
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCANNER = ROOT / "skill-auditor" / "scripts" / "scan_skill.py"
FIXTURES = ROOT / "tests" / "fixtures"

passed = failed = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global passed, failed
    if condition:
        passed += 1
        print(f"  ok    {name}")
    else:
        failed += 1
        print(f"  FALLA {name}" + (f"  -> {detail}" if detail else ""))


def scan(target: Path):
    proc = subprocess.run([sys.executable, "-I", str(SCANNER), str(target), "--json"],
                          capture_output=True, text=True, timeout=120)
    try:
        data = json.loads(proc.stdout) if proc.stdout.strip() else {}
    except ValueError:
        data = {}
    return proc.returncode, data, proc


def rules_of(data) -> set:
    return {f["rule"] for f in data.get("findings", [])}


print("1. Skill limpia")
code, data, _ = scan(FIXTURES / "clean-skill")
check("código de salida 0", code == 0, str(code))
check("veredicto sin hallazgos", data.get("verdict") == "SIN HALLAZGOS RELEVANTES", str(data.get("verdict")))
check("ningún hallazgo", not data.get("findings"), str(len(data.get("findings", []))))

print("2. Skill de riesgo (fixture inerte)")
code, data, _ = scan(FIXTURES / "risky-skill")
found = rules_of(data)
check("código de salida 2", code == 2, str(code))
check("veredicto NO INSTALAR", data.get("verdict") == "NO INSTALAR", str(data.get("verdict")))
expected = {
    "PIPE_TO_SHELL", "INJ_SECRECY", "INJ_IGNORE", "INJ_HIDDEN_CMD", "OBFUSCATED_EXEC", "EXFIL_COMBO",
    "TOOLS_UNRESTRICTED", "FORCED_TRIGGER", "SENSITIVE_PATH", "PERSISTENCE", "ENV_DUMP", "EXFIL_SERVICE",
    "DECEPTIVE_LINK", "MCP_NO_TLS", "MCP_UNPINNED", "MCP_PLAIN_SECRET",
}
check("detecta todas las reglas esperadas", expected <= found, f"faltan: {sorted(expected - found)}")
check("no hay duplicados (regla, archivo, línea)",
      len({(f["rule"], f["file"], f["line"], f["message"]) for f in data["findings"]}) == len(data["findings"]))

print("3. Unicode oculto")
with tempfile.TemporaryDirectory() as tmp:
    skill = Path(tmp) / "uni"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: uni-test\ndescription: prueba\n---\nhola‮ mundo \U000E0041\U000E0042 fin​​​​\n",
        encoding="utf-8")
    code, data, _ = scan(skill)
    found = rules_of(data)
    check("caracteres tag (crítico)", "UNICODE_TAGS" in found)
    check("control bidireccional", "UNICODE_BIDI" in found)
    check("ancho cero", "UNICODE_ZERO_WIDTH" in found)
    check("código de salida 2", code == 2, str(code))

print("4. Zip con ruta maliciosa")
with tempfile.TemporaryDirectory() as tmp:
    evil = Path(tmp) / "evil.zip"
    with zipfile.ZipFile(evil, "w") as z:
        z.writestr("skill/SKILL.md", "---\nname: x\ndescription: y\n---\nhola")
        z.writestr("../../escape.txt", "no debe salir")
    code, _, proc = scan(evil)
    check("se rechaza (código distinto de 0)", code != 0, str(code))
    check("mensaje de ruta insegura", "insegura" in (proc.stdout + proc.stderr))
    check("no se escribió fuera", not (Path(tmp).parent / "escape.txt").exists())

print("5. Paquete .skill")
with tempfile.TemporaryDirectory() as tmp:
    pkg = Path(tmp) / "ok.skill"
    with zipfile.ZipFile(pkg, "w") as z:
        for f in (FIXTURES / "clean-skill").rglob("*"):
            if f.is_file():
                z.write(f, "clean-skill/" + str(f.relative_to(FIXTURES / "clean-skill")))
    code, data, _ = scan(pkg)
    check("sin hallazgos y código 0", code == 0 and not data.get("findings"), str(code))

print("6. Higiene del código fuente")
src = SCANNER.read_text(encoding="utf-8")
invisibles = re.findall("[​-‏‪-‮⁠-⁤⁦-⁩﻿\U000E0000-\U000E007F]", src)
check("scan_skill.py sin caracteres invisibles", not invisibles, f"{len(invisibles)} encontrados")

print(f"\n{passed} correctas, {failed} fallidas")
sys.exit(1 if failed else 0)
