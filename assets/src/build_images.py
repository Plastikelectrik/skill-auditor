#!/usr/bin/env python3
"""Genera las imágenes SVG del README de Skill Auditor, en español e inglés.
Generates the Skill Auditor README images as SVG, in Spanish and English.

Uso / Usage:
    python3 build_images.py [carpeta_salida]      # por defecto, esta misma carpeta

Escribe `<nombre>.<idioma>.svg` (p. ej. `header.en.svg`). Después, `python3 render_png.py`
los convierte a `assets/<idioma>/<nombre>.png` (necesita Playwright + Chromium y la
tipografía Inter). Los PNG son los que enlazan los README para que se vean igual en
cualquier navegador. Para añadir un idioma, añade una entrada a `STR`.
"""
import sys
from pathlib import Path
from xml.sax.saxutils import escape

# ---------------------------------------------------------------- paleta y tipografía
BG0, BG1 = "#0B1220", "#101C36"
PANEL, PANEL2, BORDER = "#131D33", "#18264A", "#2A3A5C"
TEXT, MUTED, FAINT = "#E8EEF8", "#93A4C3", "#5F7196"
TEAL, RED, AMBER, GREEN, BLUE = "#2DD4BF", "#F87171", "#FBBF24", "#4ADE80", "#60A5FA"
SANS = "Inter, 'Segoe UI', Helvetica, Arial, sans-serif"
MONO = "'DejaVu Sans Mono', 'SF Mono', Menlo, Consolas, monospace"
SEV_COLOR = {"C": RED, "H": AMBER, "M": BLUE}

# ---------------------------------------------------------------- textos por idioma
STR = {
    "es": {
        "sev": {"C": "CRÍTICO", "H": "ALTO", "M": "MEDIO"},
        "header": {
            "aria": "Skill Auditor: revisa cualquier skill o servidor MCP antes de instalarlo",
            "pill": "AGENT SKILLS · MCP · SEGURIDAD",
            "sub1": "Revisa cualquier skill o servidor MCP",
            "sub2": "antes de instalarlo.",
            "chips": ["Sin ejecutar nada", "Archivo y línea", "Veredicto claro"],
        },
        "how": {
            "aria": "Cómo funciona Skill Auditor: aislar, escanear, leer y decidir",
            "title": "Cómo funciona",
            "sub": "Cuatro pasos, de la carpeta sospechosa a un veredicto que puedes defender.",
            "steps": [
                ("Aislar", ["Carpeta, .zip, .skill", "o repo de GitHub. Se", "extrae con protección", "contra rutas peligrosas."]),
                ("Escanear", ["Reglas sobre scripts,", "texto y configuración.", "Cruza señales: claves", "+ red = exfiltración."]),
                ("Leer", ["Revisión manual de", "SKILL.md y scripts:", "¿cada permiso encaja", "con su propósito?"]),
                ("Decidir", ["Informe con archivo y", "línea de cada hallazgo", "y una decisión clara", "para el usuario."]),
            ],
            "banner": "Nada del objetivo se ejecuta jamás: ni scripts, ni instaladores, ni «pruebas rápidas».",
        },
        "risk": {
            "aria": "Familias de riesgo que detecta Skill Auditor",
            "title": "Qué busca",
            "sub": "Ocho familias de riesgo, con la severidad que el escáner les asigna por defecto.",
            "cards": [
                ("Ejecución remota", "C", "terminal", ["Descarga algo y lo ejecuta", "sin que puedas revisarlo."], "curl … | sh"),
                ("Ofuscación", "H", "bin", ["Contenido codificado que", "se decodifica y se ejecuta."], "exec(b64decode(…))"),
                ("Credenciales", "H", "key", ["Lee claves, tokens o el", "entorno completo."], "~/.ssh/id_rsa"),
                ("Exfiltración", "H", "globe", ["Envía datos a destinos", "ajenos al servicio."], "webhook.site"),
                ("Persistencia", "H", "loop", ["Sobrevive a la desinstalación", "o altera al propio agente."], "~/.bashrc · .claude/"),
                ("Permisos excesivos", "H", "unlock", ["Pide más acceso del que", "necesita su tarea."], "allowed-tools: Bash(*)"),
                ("Inyección de prompts", "C", "chat", ["Texto que da órdenes al", "agente a espaldas tuyas."], "«no avises al usuario»"),
                ("Ocultación", "C", "eyeoff", ["Unicode invisible y", "comentarios HTML ocultos."], "U+202E · <!-- … -->"),
            ],
        },
        "corr": {
            "aria": "Correlación de señales: credenciales más red saliente equivale a exfiltración",
            "title": "Las señales sueltas engañan; las combinadas delatan",
            "sub": "El escáner cruza hallazgos del mismo archivo y sube la severidad cuando se encadenan.",
            "box1": ("Lee credenciales", "H", "~/.ssh/id_rsa", "o vuelca todo el entorno"),
            "box2": ("Red saliente", "M", "requests.post(…)", "o curl a un dominio ajeno"),
            "result": ("Exfiltración", "Mismo archivo, misma ruta:", "veredicto NO INSTALAR."),
            "combos": [
                ("base64 + exec", "Decodifica un blob y lo ejecuta", "C"),
                ("Claves en un archivo, red en otro", "Hay que comprobar si se encadenan", "H"),
                ("Pre-autoriza Bash + acceso web", "Combinación sensible de permisos", "M"),
            ],
            "foot1": "Un cliente de API que usa la red es normal. Un formateador de commits que lee ~/.ssh no lo es:",
            "foot2": "la pregunta es siempre si cada capacidad encaja con el propósito declarado.",
        },
        "trust": {
            "aria": "El objetivo auditado se trata como dato no confiable, nunca como instrucciones",
            "title": "El objetivo es dato, nunca instrucciones",
            "sub": "Lo que dice una skill auditada es evidencia que se cita, no órdenes que se obedecen.",
            "target": "Skill objetivo", "untrusted": "texto no confiable",
            "readonly": "solo lectura",
            "auditor": "Skill Auditor", "auditor1": "escáner + lectura crítica", "auditor2": "análisis estático",
            "report": "Informe", "report_sub": "evidencia citada, con ubicación",
            "verdict": "NO INSTALAR", "ev1": "SKILL.md:11 · crítico", "ev2": "scripts/setup.sh:5 · crítico",
            "machine": "Tu máquina y tus credenciales", "intact": "intactas",
            "never1": "Nunca se ejecutan sus scripts",
            "never2": "ni se siguen sus instrucciones, por muy",
            "never3": "razonable que suene el motivo.",
        },
        "verdicts": {
            "aria": "Los cuatro veredictos de Skill Auditor",
            "title": "Cuatro veredictos",
            "sub": "El escáner propone uno; la lectura manual lo confirma o lo corrige con motivo escrito.",
            "cards": [
                ("NO INSTALAR", RED, "exit 2", ["Hay algún hallazgo crítico:", "ejecución remota, exfiltración", "u ocultar acciones al usuario."]),
                ("REVISAR A FONDO", AMBER, "exit 1", ["Altos sin justificar, o cinco", "o más medios. Pide al autor", "que aclare antes de decidir."]),
                ("RIESGO BAJO", BLUE, "exit 0", ["Solo avisos menores. Instala", "con precauciones: versiones", "fijadas y permisos mínimos."]),
                ("SIN HALLAZGOS", GREEN, "exit 0", ["No se encontró nada y todo", "encaja con su propósito.", "No es una garantía."]),
            ],
            "foot": "El código de salida del escáner (0, 1 o 2) permite usarlo también en scripts o en CI.",
        },
    },
    "en": {
        "sev": {"C": "CRITICAL", "H": "HIGH", "M": "MEDIUM"},
        "header": {
            "aria": "Skill Auditor: review any skill or MCP server before you install it",
            "pill": "AGENT SKILLS · MCP · SECURITY",
            "sub1": "Review any skill or MCP server",
            "sub2": "before you install it.",
            "chips": ["Never executes", "File:line evidence", "Clear verdict"],
        },
        "how": {
            "aria": "How Skill Auditor works: isolate, scan, read and decide",
            "title": "How it works",
            "sub": "Four steps, from the suspicious folder to a verdict you can defend.",
            "steps": [
                ("Isolate", ["Folder, .zip, .skill or", "a downloaded repo.", "Extraction blocks unsafe", "paths and symlinks."]),
                ("Scan", ["Rules over scripts, text", "and config. Signals are", "cross-checked: keys +", "network = exfiltration."]),
                ("Read", ["Guided manual review of", "SKILL.md and scripts:", "does every permission", "match its purpose?"]),
                ("Decide", ["A report with file and", "line for every finding", "and a clear decision", "for the user."]),
            ],
            "banner": "Nothing from the target ever runs: no scripts, no installers, no “quick tests”.",
        },
        "risk": {
            "aria": "Risk families that Skill Auditor detects",
            "title": "What it looks for",
            "sub": "Eight risk families, with the severity the scanner assigns by default.",
            "cards": [
                ("Remote execution", "C", "terminal", ["Downloads code and runs it", "before you can review it."], "curl … | sh"),
                ("Obfuscation", "H", "bin", ["Encoded content that gets", "decoded and executed."], "exec(b64decode(…))"),
                ("Credentials", "H", "key", ["Reads keys, tokens or the", "entire environment."], "~/.ssh/id_rsa"),
                ("Exfiltration", "H", "globe", ["Sends data to destinations", "unrelated to the service."], "webhook.site"),
                ("Persistence", "H", "loop", ["Outlives uninstallation or", "alters the agent itself."], "~/.bashrc · .claude/"),
                ("Excess permissions", "H", "unlock", ["Asks for more access than", "its task needs."], "allowed-tools: Bash(*)"),
                ("Prompt injection", "C", "chat", ["Text that gives the agent", "orders behind your back."], "“don't tell the user”"),
                ("Concealment", "C", "eyeoff", ["Invisible Unicode and", "hidden HTML comments."], "U+202E · <!-- … -->"),
            ],
        },
        "corr": {
            "aria": "Signal correlation: credentials plus outbound network equals exfiltration",
            "title": "Isolated signals mislead; combined ones give it away",
            "sub": "The scanner cross-checks findings in the same file and raises severity when they chain.",
            "box1": ("Reads credentials", "H", "~/.ssh/id_rsa", "or dumps the whole environment"),
            "box2": ("Outbound network", "M", "requests.post(…)", "or curl to a foreign domain"),
            "result": ("Exfiltration", "Same file, same path:", "verdict: DO NOT INSTALL."),
            "combos": [
                ("base64 + exec", "Decodes a blob and runs it", "C"),
                ("Keys here, network there", "Check whether they chain up", "H"),
                ("Pre-approved Bash + web", "Sensitive permission combo", "M"),
            ],
            "foot1": "An API client using the network is normal. A commit formatter that reads ~/.ssh is not:",
            "foot2": "the question is always whether each capability fits the declared purpose.",
        },
        "trust": {
            "aria": "The audited target is treated as untrusted data, never as instructions",
            "title": "The target is data, never instructions",
            "sub": "What an audited skill says is evidence to quote, not orders to follow.",
            "target": "Target skill", "untrusted": "untrusted text",
            "readonly": "read-only",
            "auditor": "Skill Auditor", "auditor1": "scanner + critical reading", "auditor2": "static analysis",
            "report": "Report", "report_sub": "quoted evidence, with location",
            "verdict": "DO NOT INSTALL", "ev1": "SKILL.md:11 · critical", "ev2": "scripts/setup.sh:5 · critical",
            "machine": "Your machine and credentials", "intact": "untouched",
            "never1": "Its scripts are never run",
            "never2": "and its instructions are never followed,",
            "never3": "however reasonable the excuse sounds.",
        },
        "verdicts": {
            "aria": "The four Skill Auditor verdicts",
            "title": "Four verdicts",
            "sub": "The scanner proposes one; manual reading confirms it or corrects it with a written reason.",
            "cards": [
                ("DO NOT INSTALL", RED, "exit 2 · NO INSTALAR", ["Any critical finding:", "remote execution, exfiltration", "or hiding actions from the user."]),
                ("REVIEW IN DEPTH", AMBER, "exit 1 · REVISAR A FONDO", ["Unjustified highs, or five or", "more mediums. Ask the author", "to clarify before deciding."]),
                ("LOW RISK", BLUE, "exit 0 · RIESGO BAJO", ["Only minor warnings. Install", "with care: pinned versions", "and minimal permissions."]),
                ("NO FINDINGS", GREEN, "exit 0 · SIN HALLAZGOS", ["Nothing found and everything", "fits its purpose.", "Not a guarantee."]),
            ],
            "foot": "The scanner's exit code (0, 1 or 2) lets you use it in scripts or CI too.",
        },
    },
}


# ---------------------------------------------------------------- primitivas
def t(x, y, s, size=18, weight=400, fill=TEXT, anchor="start", family=SANS, extra=""):
    return (f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" font-weight="{weight}" '
            f'fill="{fill}" text-anchor="{anchor}" {extra}>{escape(s)}</text>')


def rect(x, y, w, h, r=12, fill=PANEL, stroke=BORDER, sw=1.5, extra=""):
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill}" '
            f'stroke="{stroke}" stroke-width="{sw}" {extra}/>')


def lines(x, y, rows, size=16, gap=24, fill=MUTED, weight=400, family=SANS):
    return "".join(t(x, y + i * gap, row, size, weight, fill, family=family) for i, row in enumerate(rows))


def pill_w(label, size=12):
    return int(len(label) * size * 0.66 + 24)


def pill(x, y, label, color, size=12, h=26):
    w = pill_w(label, size)
    return (rect(x, y, w, h, h / 2, fill=color + "26", stroke=color + "99", sw=1.2)
            + t(x + w / 2, y + h / 2 + size * 0.36, label, size, 700, color, "middle", extra='letter-spacing="1"'))


def right_pill(right, y, label, color, size=12, h=26):
    return pill(right - pill_w(label, size), y, label, color, size, h)


def svg(w, h, body, title):
    defs = (f'<defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">'
            f'<stop offset="0" stop-color="{BG0}"/><stop offset="1" stop-color="{BG1}"/></linearGradient>'
            f'<radialGradient id="glow"><stop offset="0" stop-color="{TEAL}" stop-opacity=".22"/>'
            f'<stop offset="1" stop-color="{TEAL}" stop-opacity="0"/></radialGradient>'
            f'<radialGradient id="redglow"><stop offset="0" stop-color="{RED}" stop-opacity=".25"/>'
            f'<stop offset="1" stop-color="{RED}" stop-opacity="0"/></radialGradient>'
            f'<pattern id="dots" width="32" height="32" patternUnits="userSpaceOnUse">'
            f'<circle cx="2" cy="2" r="1.2" fill="#ffffff" fill-opacity=".05"/></pattern></defs>')
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
            f'role="img" aria-label="{escape(title)}"><title>{escape(title)}</title>{defs}'
            f'<rect width="{w}" height="{h}" fill="url(#bg)"/><rect width="{w}" height="{h}" fill="url(#dots)"/>'
            f'{body}</svg>')


def heading(title, subtitle):
    return (t(64, 86, title, 42, 800, TEXT, extra='letter-spacing="-1"')
            + t(64, 122, subtitle, 20, 400, MUTED))


# ---------------------------------------------------------------- iconos (caja de ~40x40)
ICONS = {
    "folder": '<path d="M2 10a3 3 0 0 1 3-3h10l5 6h18a3 3 0 0 1 3 3v18a3 3 0 0 1-3 3H5a3 3 0 0 1-3-3z"/>',
    "scan": '<circle cx="17" cy="17" r="12"/><path d="M26 26l11 11"/>',
    "eye": '<path d="M2 20C10 6 30 6 38 20 30 34 10 34 2 20z"/><circle cx="20" cy="20" r="6"/>',
    "eyeoff": '<path d="M2 20C10 6 30 6 38 20 30 34 10 34 2 20z"/><circle cx="20" cy="20" r="6"/><path d="M6 36L34 4"/>',
    "shield": '<path d="M20 3l15 6v11c0 9-7 15-15 18C12 35 5 29 5 20V9z"/><path d="M13 20l5 5 10-11"/>',
    "key": '<circle cx="11" cy="20" r="8"/><path d="M19 20h19M31 20v8M37 20v6"/>',
    "globe": '<circle cx="20" cy="20" r="16"/><ellipse cx="20" cy="20" rx="7" ry="16"/><path d="M4 20h32"/>',
    "lock": '<rect x="7" y="18" width="26" height="19" rx="4"/><path d="M13 18v-6a7 7 0 0 1 14 0v6"/>',
    "unlock": '<rect x="7" y="18" width="26" height="19" rx="4"/><path d="M13 18v-6a7 7 0 0 1 13-3"/>',
    "terminal": '<rect x="2" y="5" width="36" height="30" rx="5"/><path d="M10 15l8 6-8 6M22 28h9"/>',
    "loop": '<path d="M33 20a13 13 0 1 1-4-9.5"/><path d="M31 3v9h-9"/>',
    "chat": '<path d="M5 6h30a3 3 0 0 1 3 3v17a3 3 0 0 1-3 3H18l-9 8v-8H5a3 3 0 0 1-3-3V9a3 3 0 0 1 3-3z"/>',
    "bin": '<rect x="3" y="3" width="34" height="34" rx="6"/>',
    "alert": '<path d="M20 4l17 30H3z"/><path d="M20 15v9M20 29v1"/>',
}


def icon(name, x, y, color=TEAL, sw=3):
    extra = ""
    if name == "bin":
        extra = (f'<text x="20" y="26" font-family="{MONO}" font-size="15" font-weight="700" fill="{color}" '
                 f'stroke="none" text-anchor="middle">01</text>')
    return (f'<g transform="translate({x},{y})" fill="none" stroke="{color}" stroke-width="{sw}" '
            f'stroke-linecap="round" stroke-linejoin="round">{ICONS[name]}{extra}</g>')


def arrow(x1, y, x2, color=FAINT, w=3):
    return (f'<path d="M{x1} {y}H{x2 - 8}" stroke="{color}" stroke-width="{w}" stroke-linecap="round" fill="none"/>'
            f'<path d="M{x2 - 14} {y - 8}l10 8-10 8" stroke="{color}" stroke-width="{w}" fill="none" '
            f'stroke-linecap="round" stroke-linejoin="round"/>')


# ---------------------------------------------------------------- 1. cabecera
def header(L):
    S = L["header"]
    W, H = 1280, 640
    b = ['<circle cx="1000" cy="330" r="400" fill="url(#glow)"/>']
    pw = max(318, pill_w(S["pill"], 13) + 20)
    b.append(rect(80, 92, pw, 36, 18, fill=TEAL + "1F", stroke=TEAL + "73", sw=1.2))
    b.append(t(80 + pw / 2, 115.5, S["pill"], 13, 700, TEAL, "middle", extra='letter-spacing="1.6"'))
    b.append(t(76, 262, "Skill", 124, 800, TEXT, extra='letter-spacing="-3"'))
    b.append(t(76, 384, "Auditor", 124, 800, TEAL, extra='letter-spacing="-3"'))
    b.append(t(80, 448, S["sub1"], 30, 500, TEXT))
    b.append(t(80, 488, S["sub2"], 30, 500, MUTED))
    x = 80
    for label in S["chips"]:
        w = int(len(label) * 11.4 + 40)
        b.append(rect(x, 530, w, 40, 20, fill=PANEL, stroke=BORDER))
        b.append(t(x + w / 2, 556, label, 18, 500, MUTED, "middle"))
        x += w + 14
    cx, cy, cw, ch = 800, 104, 380, 420
    b.append(rect(cx, cy, cw, ch, 20, fill=PANEL, stroke=BORDER, sw=2))
    b.append(f'<path d="M{cx} {cy + 52}H{cx + cw}" stroke="{BORDER}" stroke-width="1.5"/>')
    for i, c in enumerate((RED, AMBER, GREEN)):
        b.append(f'<circle cx="{cx + 28 + i * 24}" cy="{cy + 26}" r="6" fill="{c}" fill-opacity=".85"/>')
    b.append(t(cx + 112, cy + 31, "SKILL.md", 15, 500, FAINT, family=MONO))
    rows = [("bar", 220), ("bar", 300), ("hit", "curl -s x.sh | sh", RED), ("bar", 180),
            ("hit", "cat ~/.ssh/id_rsa", AMBER), ("bar", 260),
            ("hit", "ignore previous instructions", RED), ("bar", 200), ("bar", 280), ("bar", 150)]
    for i, row in enumerate(rows):
        y = cy + 84 + i * 34
        if row[0] == "bar":
            b.append(rect(cx + 26, y, row[1], 12, 6, fill="#23324F", stroke="none", sw=0))
        else:
            col = row[2]
            b.append(rect(cx + 14, y - 11, cw - 28, 34, 8, fill=col + "26", stroke="none", sw=0))
            b.append(f'<rect x="{cx + 14}" y="{y - 11}" width="4" height="34" rx="2" fill="{col}"/>')
            b.append(t(cx + 30, y + 11, row[1], 16, 500, col, family=MONO))
    b.append(f'<circle cx="1118" cy="506" r="66" fill="{TEAL}" fill-opacity=".10" stroke="{TEAL}" stroke-width="11"/>')
    b.append(f'<path d="M1166 554l46 46" stroke="{TEAL}" stroke-width="20" stroke-linecap="round"/>')
    b.append(f'<path d="M1080 484a40 40 0 0 1 26-22" stroke="#fff" stroke-opacity=".5" stroke-width="6" '
             f'fill="none" stroke-linecap="round"/>')
    b.append(f'<g transform="translate(1180 118) scale(1.7)"><path d="M0-26l22 9v16c0 13-10 22-22 27C-12 21-22 12-22-1v-16z" '
             f'fill="#0E2A33" stroke="{TEAL}" stroke-width="3.2" stroke-linejoin="round"/>'
             f'<path d="M-9 0l7 7 13-15" fill="none" stroke="{TEAL}" stroke-width="4" stroke-linecap="round" '
             f'stroke-linejoin="round"/></g>')
    return svg(W, H, "".join(b), S["aria"])


# ---------------------------------------------------------------- 2. cómo funciona
def how_it_works(L):
    S = L["how"]
    W, H = 1280, 580
    b = [heading(S["title"], S["sub"])]
    icons = ["folder", "scan", "eye", "shield"]
    w, gap, x0, y0, h = 264, 32, 64, 160, 290
    for i, (title, rows) in enumerate(S["steps"]):
        x = x0 + i * (w + gap)
        b.append(rect(x, y0, w, h, 20, fill=PANEL, stroke=BORDER, sw=1.5))
        b.append(f'<circle cx="{x + 42}" cy="{y0 + 46}" r="22" fill="{TEAL}" fill-opacity=".14" stroke="{TEAL}" stroke-width="2"/>')
        b.append(t(x + 42, y0 + 53, str(i + 1), 21, 800, TEAL, "middle"))
        b.append(icon(icons[i], x + w - 68, y0 + 28, TEAL, 3))
        b.append(t(x + 28, y0 + 118, title, 28, 700, TEXT))
        b.append(lines(x + 28, y0 + 158, rows, 17, 28))
        if i < 3:
            b.append(arrow(x + w + 4, y0 + 46, x + w + gap - 4, FAINT, 3))
    b.append(rect(64, 480, 1152, 58, 16, fill=RED + "14", stroke=RED + "66", sw=1.5))
    b.append(icon("lock", 88, 489, RED, 2.6))
    b.append(t(144, 516, S["banner"], 20, 600, TEXT))
    return svg(W, H, "".join(b), S["aria"])


# ---------------------------------------------------------------- 3. mapa de riesgos
def risk_map(L):
    S = L["risk"]
    W, H = 1280, 760
    b = [heading(S["title"], S["sub"])]
    w, h, gx, gy, x0, y0 = 276, 262, 16, 20, 64, 160
    for i, (title, sev, ic, desc, ex) in enumerate(S["cards"]):
        x = x0 + (i % 4) * (w + gx)
        y = y0 + (i // 4) * (h + gy)
        col, label = SEV_COLOR[sev], L["sev"][sev]
        b.append(rect(x, y, w, h, 18, fill=PANEL, stroke=BORDER))
        b.append(f'<path d="M{x + 18} {y}H{x + w - 18}" stroke="{col}" stroke-width="4" stroke-linecap="round"/>')
        b.append(icon(ic, x + 24, y + 30, col, 2.8))
        b.append(right_pill(x + w - 24, y + 34, label, col))
        b.append(t(x + 24, y + 108, title, 22, 700, TEXT))
        b.append(lines(x + 24, y + 140, desc, 16, 24))
        b.append(rect(x + 20, y + h - 62, w - 40, 38, 10, fill="#0B1424", stroke=BORDER, sw=1))
        b.append(t(x + 34, y + h - 37, ex, 14, 500, col, family=MONO))
    return svg(W, H, "".join(b), S["aria"])


# ---------------------------------------------------------------- 4. correlación de señales
def correlation(L):
    S = L["corr"]
    W, H = 1280, 620
    b = [t(64, 86, S["title"], 40, 800, TEXT, extra='letter-spacing="-1"'),
         t(64, 122, S["sub"], 20, 400, MUTED)]
    y0, h, w = 160, 210, 300
    for x, (title, sev, ex, sub), ic in ((64, S["box1"], "key"), (476, S["box2"], "globe")):
        col = SEV_COLOR[sev]
        b.append(rect(x, y0, w, h, 20, fill=PANEL, stroke=BORDER))
        b.append(icon(ic, x + 26, y0 + 28, col, 3))
        b.append(right_pill(x + w - 24, y0 + 32, L["sev"][sev], col))
        b.append(t(x + 26, y0 + 118, title, 26, 700, TEXT))
        b.append(t(x + 26, y0 + 156, ex, 16, 500, col, family=MONO))
        b.append(t(x + 26, y0 + 182, sub, 15, 400, MUTED))
    b.append(t(400, y0 + 118, "+", 60, 300, MUTED, "middle"))
    b.append(t(812, y0 + 118, "=", 60, 300, MUTED, "middle"))
    rx = 876
    rt, r1, r2 = S["result"]
    b.append(f'<circle cx="{rx + 170}" cy="{y0 + h / 2}" r="230" fill="url(#redglow)"/>')
    b.append(rect(rx, y0, 340, h, 20, fill="#2A1418", stroke=RED, sw=2.4))
    b.append(icon("alert", rx + 26, y0 + 28, RED, 3))
    b.append(right_pill(rx + 340 - 24, y0 + 32, L["sev"]["C"], RED))
    b.append(t(rx + 26, y0 + 118, rt, 28, 800, TEXT))
    b.append(t(rx + 26, y0 + 154, r1, 16, 500, MUTED))
    b.append(t(rx + 26, y0 + 180, r2, 16, 700, RED))
    cy, cw, gx = 402, 368, 24
    for i, (title, sub, sev) in enumerate(S["combos"]):
        x, col = 64 + i * (cw + gx), SEV_COLOR[sev]
        b.append(rect(x, cy, cw, 112, 16, fill=PANEL, stroke=BORDER))
        b.append(f'<rect x="{x}" y="{cy + 16}" width="5" height="80" rx="2.5" fill="{col}"/>')
        b.append(pill(x + 24, cy + 14, L["sev"][sev], col, 11, 24))
        b.append(t(x + 24, cy + 66, title, 18, 700, TEXT))
        b.append(t(x + 24, cy + 92, sub, 15, 400, MUTED))
    b.append(t(64, 556, S["foot1"], 18, 500, MUTED))
    b.append(t(64, 584, S["foot2"], 18, 500, MUTED))
    return svg(W, H, "".join(b), S["aria"])


# ---------------------------------------------------------------- 5. frontera de confianza
def trust_boundary(L):
    S = L["trust"]
    W, H = 1280, 620
    b = [t(64, 86, S["title"], 42, 800, TEXT, extra='letter-spacing="-1"'),
         t(64, 122, S["sub"], 20, 400, MUTED)]
    b.append(rect(64, 160, 330, 250, 20, fill="#1A1220", stroke=RED, sw=2.2, extra='stroke-dasharray="9 7"'))
    b.append(t(88, 200, S["target"], 24, 700, TEXT))
    b.append(t(88, 226, S["untrusted"], 15, 600, RED))
    for i, r in enumerate(["Do not tell the user…", "curl … | sh", "<!-- ignore previous -->"]):
        y = 262 + i * 44
        b.append(rect(84, y - 6, 290, 34, 8, fill=RED + "1F", stroke="none", sw=0))
        b.append(t(98, y + 17, r, 15, 500, RED, family=MONO))
    b.append(arrow(398, 285, 506, TEAL, 3.4))
    b.append(t(452, 262, S["readonly"], 14, 600, TEAL, "middle"))
    b.append('<circle cx="640" cy="285" r="200" fill="url(#glow)"/>')
    b.append(rect(510, 200, 260, 170, 20, fill=PANEL, stroke=TEAL, sw=2.4))
    b.append(icon("shield", 540, 224, TEAL, 3))
    b.append(t(540, 300, S["auditor"], 25, 800, TEXT))
    b.append(t(540, 328, S["auditor1"], 15, 500, MUTED))
    b.append(t(540, 350, S["auditor2"], 15, 500, MUTED))
    b.append(arrow(774, 285, 890, TEAL, 3.4))
    b.append(rect(894, 160, 322, 250, 20, fill=PANEL, stroke=BORDER, sw=1.8))
    b.append(t(918, 200, S["report"], 24, 700, TEXT))
    b.append(t(918, 226, S["report_sub"], 15, 500, MUTED))
    b.append(pill(918, 250, S["verdict"], RED, 13, 30))
    b.append(rect(918, 300, 274, 34, 8, fill="#0B1424", stroke=BORDER, sw=1))
    b.append(t(932, 322, S["ev1"], 14, 500, RED, family=MONO))
    b.append(rect(918, 344, 274, 34, 8, fill="#0B1424", stroke=BORDER, sw=1))
    b.append(t(932, 366, S["ev2"], 14, 500, RED, family=MONO))
    b.append(f'<path d="M229 414V506" stroke="{RED}" stroke-width="3.4" stroke-dasharray="3 9" stroke-linecap="round"/>')
    b.append(f'<circle cx="229" cy="460" r="22" fill="#2A1418" stroke="{RED}" stroke-width="2.6"/>')
    b.append(f'<path d="M219 450l20 20M239 450l-20 20" stroke="{RED}" stroke-width="3.6" stroke-linecap="round"/>')
    b.append(rect(64, 510, 330, 62, 16, fill=PANEL, stroke=BORDER, sw=1.8))
    b.append(t(88, 536, S["machine"], 18, 700, TEXT))
    b.append(t(88, 558, S["intact"], 15, 500, MUTED))
    b.append(t(274, 450, S["never1"], 20, 700, TEXT))
    b.append(t(274, 476, S["never2"], 17, 400, MUTED))
    b.append(t(274, 498, S["never3"], 17, 400, MUTED))
    return svg(W, H, "".join(b), S["aria"])


# ---------------------------------------------------------------- 6. veredictos
def verdicts(L):
    S = L["verdicts"]
    W, H = 1280, 470
    b = [t(64, 86, S["title"], 42, 800, TEXT, extra='letter-spacing="-1"'),
         t(64, 122, S["sub"], 20, 400, MUTED)]
    w, gap, y0, h = 276, 16, 160, 230
    for i, (name, col, code, rows) in enumerate(S["cards"]):
        x = 64 + i * (w + gap)
        b.append(rect(x, y0, w, h, 18, fill=PANEL, stroke=BORDER))
        b.append(f'<path d="M{x + 18} {y0}H{x + w - 18}" stroke="{col}" stroke-width="5" stroke-linecap="round"/>')
        b.append(f'<circle cx="{x + 40}" cy="{y0 + 52}" r="14" fill="{col}" fill-opacity=".2" stroke="{col}" stroke-width="2.4"/>')
        b.append(t(x + 66, y0 + 59, name, 20, 800, col))
        b.append(lines(x + 24, y0 + 112, rows, 16, 26))
        b.append(pill(x + 24, y0 + h - 46, code, col, 12, 26))
    b.append(t(64, 430, S["foot"], 18, 500, MUTED))
    return svg(W, H, "".join(b), S["aria"])


IMAGES = {
    "header": header, "how-it-works": how_it_works, "risk-map": risk_map,
    "correlation": correlation, "trust-boundary": trust_boundary, "verdicts": verdicts,
}

if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent
    out.mkdir(parents=True, exist_ok=True)
    for lang, strings in STR.items():
        for name, fn in IMAGES.items():
            target = out / f"{name}.{lang}.svg"
            target.write_text(fn(strings), encoding="utf-8")
            print("escrito", target)
