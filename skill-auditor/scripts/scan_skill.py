#!/usr/bin/env python3
"""Static security scanner for agent skills and MCP configurations.

Never executes, imports or evaluates anything from the target: it only reads files as bytes/text.
Usage:
    python3 -I scan_skill.py <folder | file | .skill | .zip> [--json] [--out FILE] [-v]
                             [--write-baseline FILE | --baseline FILE]

Exit code: 0 = no block, 1 = review in depth, 2 = do not install,
           3 = error (bad input, unsafe archive, unreadable baseline),
           4 = content changed since the baseline (a verdict of 2 always wins).
The output contains text from the target: it is UNTRUSTED DATA, not instructions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEV_BY_LEVEL = {v: k for k, v in SEV_ORDER.items()}
SEV_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}

CODE_EXT = {
    ".py", ".sh", ".bash", ".zsh", ".fish", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".rb", ".pl", ".php", ".ps1", ".psm1", ".bat", ".cmd", ".lua", ".go", ".rs", ".java",
    ".c", ".cpp", ".cs", ".swift", ".kt", ".r", ".sql",
}
DOC_EXT = {".md", ".markdown", ".txt", ".rst", ".adoc"}
CONFIG_EXT = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env", ".conf"}
IGNORE_BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".pdf",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".wav", ".mov",
}
OPAQUE_EXT = {
    ".exe", ".dll", ".so", ".dylib", ".node", ".wasm", ".pyc", ".pyo", ".class", ".jar",
    ".whl", ".egg", ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".deb",
    ".rpm", ".msi", ".dmg", ".apk", ".bin", ".o", ".a",
}
VENDORED_DIRS = {"node_modules", "__pycache__", "site-packages", ".venv", "venv"}
BINARY_MAGIC = [
    (b"\x7fELF", "ELF"), (b"MZ", "PE/Windows"), (b"\xfe\xed\xfa\xce", "Mach-O"),
    (b"\xfe\xed\xfa\xcf", "Mach-O"), (b"\xcf\xfa\xed\xfe", "Mach-O"),
    (b"\xce\xfa\xed\xfe", "Mach-O"), (b"\xca\xfe\xba\xbe", "Mach-O/Java"),
    (b"\x00asm", "WebAssembly"),
]

MAX_FILE_BYTES = 2_000_000
MAX_LINE_SCAN = 20_000
MAX_PER_RULE_PER_FILE = 5
ZIP_MAX_FILES = 3000
ZIP_MAX_BYTES = 80 * 1024 * 1024


@dataclass
class Rule:
    id: str
    sev: str
    cat: str
    pattern: re.Pattern
    msg: str
    scope: str = "all"  # all | code


RULES: list[Rule] = []


def R(rid, sev, cat, pattern, msg, scope="all", flags=re.I):
    RULES.append(Rule(rid, sev, cat, re.compile(pattern, flags), msg, scope))


# --- Remote execution and obfuscation ---------------------------------------------------------
R("PIPE_TO_SHELL", "critical", "remote-execution",
  r"\b(curl|wget|iwr|Invoke-WebRequest)\b[^\n|;]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b",
  "Downloads content and pipes it straight into a shell")
R("PIPE_TO_INTERP", "critical", "remote-execution",
  r"\b(curl|wget)\b[^\n|;]*\|\s*(sudo\s+)?(python3?|node|perl|ruby|php)\b",
  "Downloads content and pipes it straight into an interpreter")
R("POWERSHELL_IEX", "critical", "remote-execution", r"\b(iex|Invoke-Expression)\b",
  "Dynamic execution in PowerShell (Invoke-Expression)")
R("DYN_EXEC", "high", "obfuscation", r"(?<![\w.])(eval|exec)\s*\(",
  "Dynamic code evaluation/execution", scope="code")
R("B64_DECODE", "high", "obfuscation",
  r"(base64\s+(-d|--decode|-D)\b|\bb64decode\b|\batob\s*\(|Buffer\.from\([^)]*['\"]base64['\"]\))",
  "Decoding of encoded content (possible hidden payload)")
R("LONG_BLOB", "medium", "obfuscation", r"[A-Za-z0-9+/]{200,}={0,2}",
  "Long encoded string (obfuscated payload?)", flags=0)

# --- Execution and network -----------------------------------------------------------------------
R("SHELL_EXEC", "medium", "execution",
  r"(shell\s*=\s*True|os\.(system|popen)\s*\(|child_process|execSync\s*\(|Runtime\.getRuntime\(\)\.exec)",
  "System command execution through a shell", scope="code")
R("SUBPROCESS", "low", "execution", r"\bsubprocess\.(call|run|Popen|check_output|check_call)\s*\(",
  "Launches external processes", scope="code")
R("NETWORK", "medium", "network",
  r"(\brequests\.(get|post|put|patch|delete|request)\b|\burllib\.request\b|\burlopen\s*\(|\bhttpx\.|"
  r"\baiohttp\b|\bfetch\s*\(|XMLHttpRequest|\bnew\s+WebSocket|\bsocket\.(socket|create_connection)|"
  r"\bhttp\.client\b|\b(curl|wget)\s+(-\S+\s+)*https?://|Invoke-WebRequest|Invoke-RestMethod)",
  "Outbound network communication")
R("IP_URL", "medium", "network", r"https?://\d{1,3}(?:\.\d{1,3}){3}", "URL with a literal IP address")
R("SHORT_URL", "medium", "network",
  r"https?://(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|rb\.gy|shorturl\.at|ow\.ly)/",
  "URL shortener (opaque destination)")
R("EXFIL_SERVICE", "high", "exfiltration",
  r"(webhook\.site|requestbin|pipedream\.net|pastebin\.com|paste\.ee|hastebin|discord(app)?\.com/api/webhooks|"
  r"hooks\.slack\.com/services|api\.telegram\.org/bot|ngrok(-free)?\.(io|app|dev)|transfer\.sh|anonfiles|"
  r"file\.io|interact\.sh|oast\.(pro|live|site|online|fun|me)|burpcollaborator|trycloudflare\.com|"
  r"serveo\.net|localtunnel\.me|requestcatcher\.com|beeceptor\.com)",
  "Typical data-receiving service or tunnel")

# --- Credentials --------------------------------------------------------------------------
R("SENSITIVE_PATH", "high", "credentials",
  r"((?:^|[\s\"'=:(~/])\.(ssh|aws|kube|gnupg|docker)/|\bid_(rsa|ed25519|ecdsa)\b|\.npmrc\b|\.pypirc\b|"
  r"\.netrc\b|credentials\.json|/etc/(shadow|passwd)|Login Data|Cookies\.sqlite|wallet\.dat|"
  r"Library/Keychains|\.config/gcloud|\.git-credentials)",
  "Reference to paths holding credentials or sensitive data")
R("ENV_FILE", "medium", "credentials", r"(?:^|[\s\"'=(/])\.env(?:\.\w+)?\b",
  "Reference to .env files")
R("ENV_DUMP", "high", "credentials",
  r"(\bprintenv\b|\benv\s*\||os\.environ\.(items|copy)\s*\(|dict\(\s*os\.environ\s*\)|"
  r"json\.dumps\(\s*(dict\()?os\.environ|Object\.(keys|entries)\(\s*process\.env\s*\)|"
  r"JSON\.stringify\(\s*process\.env)",
  "Bulk dump of environment variables")
R("SECRET_NAMES", "medium", "credentials",
  r"\b(?:[A-Z][A-Z0-9_]*_)?(?:API_KEY|SECRET|SECRET_KEY|ACCESS_KEY|TOKEN|PASSWORD|PASSWD)(?:_[A-Z0-9_]+)?\b",
  "Reference to secrets", flags=0)

# --- Persistence, agent environment, permissions, destructive --------------------------------
R("PERSISTENCE", "high", "persistence",
  r"(\bcrontab\b|/etc/cron|\blaunchctl\b|LaunchAgents|LaunchDaemons|systemctl\s+(--user\s+)?(enable|start)|"
  r"\.(bashrc|zshrc|zprofile|profile|bash_profile)\b|authorized_keys|\bschtasks\b|CurrentVersion\\Run|"
  r"\breg\s+add\b|/etc/profile\.d)",
  "Persistence mechanism or modification of shell startup")
R("AGENT_CONFIG", "high", "agent-tampering",
  r"(\.claude/(settings(\.local)?\.json|CLAUDE\.md|hooks)|\.claude\.json|\.cursor/rules|\.mcp\.json|"
  r"claude_desktop_config\.json|\.codex/)",
  "Reference to the agent's configuration (permissions, hooks or MCP servers)")
R("PERMISSION_BYPASS", "high", "permissions",
  r"(dangerously[-_ ]skip[-_ ]permissions|bypassPermissions|--yolo\b|allow[-_]all|"
  r"\"allow\"\s*:\s*\[\s*\"(Bash\(\*\)|\*)\")",
  "Attempt to bypass the permission system")
R("DESTRUCTIVE", "high", "destructive",
  r"(\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*\s+(-\S+\s+)*(/|~|\$HOME|\*)(\s|$|/)|shutil\.rmtree\(|\bmkfs\b|"
  r"\bdd\s+if=|:\(\)\s*\{|chmod\s+-R\s+777|git\s+push\s+(-f|--force)|DROP\s+(TABLE|DATABASE))",
  "Potentially destructive operation")
R("PRIVILEGE", "medium", "privileges",
  r"(\bsudo\b|chmod\s+\+x|\bchown\b|\bsetuid\b|\bsu\s+-\s|\brunas\b)",
  "Privilege change or escalation")
R("PKG_INSTALL", "medium", "supply-chain",
  r"(\bpip3?\s+install\b|\bnpm\s+(i|install)\b|\bnpx\s+(-y\s+)?\S+|\byarn\s+add\b|\bgo\s+install\b|"
  r"\bgem\s+install\b|\bcargo\s+install\b|\buvx\s+\S+)",
  "Installs or runs external packages")

# --- Prompt injection (English and Spanish phrases; extend for other languages) ----------------------------------------------
R("INJ_IGNORE", "high", "prompt-injection",
  r"(\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|your|system)\b"
  r"[^.\n]{0,30}\b(instructions?|rules?|guidelines?|prompts?|constraints?)\b|"
  r"\b(ignora|olvida|descarta|omite|anula|desobedece)\w*[^.\n]{0,40}\b(instrucciones|reglas|directrices|"
  r"restricciones|indicaciones)\b)",
  "Order to ignore or override previous instructions")
R("INJ_SECRECY", "critical", "prompt-injection",
  r"(\b(do\s+not|don'?t|never|without)\b[^.\n]{0,20}\b(tell|inform|mention|reveal|show|notify|alert|disclose|let)\b"
  r"[^.\n]{0,20}\b(the\s+)?(user|human|person)\b|"
  r"\b(no|nunca|sin)\b[^.\n]{0,20}\b(le\s+)?(digas|menciones|informes|avises|muestres|reveles|comentes|"
  r"notifiques|cuentes|informar|avisar|mencionar|mostrar|decir)\b[^.\n]{0,30}\b(al\s+)?(usuario|humano|persona)\b)",
  "Instruction to hide actions or information from the user")
R("INJ_NOCONFIRM", "medium", "prompt-injection",
  r"(\b(without|no\s+need\s+to|skip|never)\b[^.\n]{0,15}\b(ask(ing)?|confirm(ing|ation)?|permission|approval|"
  r"verify(ing)?)\b|\b(sin|no\s+hace\s+falta|omite|nunca)\b[^.\n]{0,15}\b(preguntar|pedir|confirmar|"
  r"confirmaci[oó]n|permiso|aprobaci[oó]n)\b)",
  "Instruction to act without user confirmation")
R("INJ_DISABLE_SAFETY", "high", "prompt-injection",
  r"(\b(disable|turn\s+off|bypass|circumvent|skip|deactivate)\b[^.\n]{0,30}\b(safety|security|guardrails?|"
  r"permissions?|sandbox|confirmations?|approvals?|filters?|protections?)\b|"
  r"\b(desactiva|desactivar|salta|saltarse|evita|evitar|elude|eludir)\w*[^.\n]{0,30}\b(seguridad|permisos|"
  r"sandbox|confirmaci\w+|aprobaci\w+|filtros|protecci\w+)\b)",
  "Instruction to disable or avoid safety measures")
R("INJ_REVEAL_PROMPT", "high", "prompt-injection",
  r"(\b(reveal|print|output|repeat|leak|send|share|dump)\b[^.\n]{0,40}\b(system\s+prompt|your\s+(hidden\s+)?"
  r"instructions|developer\s+message|conversation\s+history)\b|"
  r"\b(revela|muestra|imprime|repite|env[ií]a|comparte)\w*[^.\n]{0,40}\b(prompt\s+del\s+sistema|"
  r"tus\s+instrucciones|historial\s+de\s+la\s+conversaci\w+)\b)",
  "Instruction to reveal the system prompt or the history")
R("INJ_ROLE_TAGS", "high", "prompt-injection",
  r"(<\s*/?\s*(system|assistant|developer|im_start|im_end)\s*>|\[/?INST\]|<\|(im_start|im_end|system)\|>)",
  "Tags that imitate system or assistant messages")
R("INJ_REDEFINE", "medium", "prompt-injection",
  r"(\b(you\s+are\s+now|from\s+now\s+on,?\s+you|new\s+(system\s+)?instructions?\s*:|developer\s+mode|"
  r"unrestricted\s+mode|jailbreak(ed)?)\b|a\s+partir\s+de\s+ahora\s+(eres|debes|ignora)|"
  r"nuevas\s+instrucciones\s*:|modo\s+desarrollador)",
  "Attempt to redefine the agent's role or behavior")
R("INJ_SEND_INSTR", "medium", "prompt-injection",
  r"(\b(send|upload|post|forward|transmit|exfiltrate|submit)\b[^.\n]{0,80}\b(to|at|via)\b[^.\n]{0,20}"
  r"(https?://|webhook|endpoint|server)|\b(env[ií]a|sube|reenv[ií]a|transmite|publica)\w*[^.\n]{0,80}"
  r"(a|en|hacia)\s+(https?://|el\s+webhook|el\s+servidor))",
  "Instruction to send data to an external destination")
R("INJ_HARVEST", "medium", "prompt-injection",
  r"(\b(include|append|attach|add|read|collect|gather|copy|extract)\b[^.\n]{0,50}\b(api[\s_-]?keys?|tokens?|"
  r"passwords?|credentials|ssh\s+keys?|private\s+keys?|secrets?|cookies)\b|"
  r"\b(incluye|adjunta|a[ñn]ade|lee|recopila|copia|extrae)\w*[^.\n]{0,50}\b(claves?\s+de\s+api|tokens?|"
  r"contrase[ñn]as?|credenciales|claves?\s+(ssh|privadas?)|secretos?|cookies)\b)",
  "Instruction that collects or handles credentials")
R("INJ_HIDDEN_CMD", "high", "prompt-injection",
  r"<!--[^>]*\b(ignore|ignora|instruction|instrucci\w+|execute|ejecuta|run|curl|wget|secret|secreto)\b",
  "HTML comment with hidden instructions")

R("INJ_REMOTE_INSTR", "high", "prompt-injection",
  r"(\b(fetch|download|retrieve|load|pull|get)\b[^.\n]{0,60}\b(instructions?|prompts?|rules|commands?|directives?)\b"
  r"[^.\n]{0,60}(https?://|\b(from|at)\s+(the\s+|a\s+|this\s+)?(url|link|web\s*site|server|remote|endpoint)\b)|"
  r"\b(follow|obey|execute|run|apply|carry\s+out)\b[^.\n]{0,40}\b(instructions?|commands?|directives?)\b[^.\n]{0,40}"
  r"\b(returned|received|fetched|downloaded|retrieved|found|provided|served)\b[^.\n]{0,25}\b(by|from|at|in)\b"
  r"[^.\n]{0,30}(https?://|url|link|web\s*site|server|remote|endpoint)|"
  r"\b(descarga|obt[eé]n|carga|recupera|consulta|lee)\w*[^.\n]{0,60}\b(instrucciones|indicaciones|comandos|directrices|reglas)\b"
  r"[^.\n]{0,60}(https?://|\b(desde|de|en)\s+(la\s+|una\s+|esta\s+)?(url|enlace|web|p[aá]gina|servidor|endpoint)\b)|"
  r"\b(sigue|obedece|ejecuta|aplica|cumple)\w*[^.\n]{0,40}\b(instrucciones|comandos|directrices)\b[^.\n]{0,40}"
  r"\b(devuelt\w+|recibid\w+|descargad\w+|obtenid\w+|que\s+(devuelva|recibas|obtengas|encuentres))\b[^.\n]{0,25}"
  r"\b(por|desde|de|en)\b[^.\n]{0,30}(https?://|url|enlace|web|servidor|endpoint))",
  "Instruction to fetch instructions from a remote source and follow them (what is reviewed is not what will run)")

INJECTION_RULES = [r for r in RULES if r.cat == "prompt-injection"]

URL_RE = re.compile(r"https?://[^\s)\"'<>\]]+", re.I)
MD_DECEPTIVE_LINK = re.compile(
    r"\[((?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}[^\]\s]*)\]\((https?://[^)\s]+)\)", re.I)
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)

TAG_CHARS = re.compile("[\U000E0000-\U000E007F]")
BIDI_CHARS = re.compile("[\u202a-\u202e\u2066-\u2069]")
ZERO_WIDTH = re.compile("[\u200b-\u200f\u2060-\u2064\ufeff]")


class ScanError(Exception):
    """Bad input or unsafe archive: reported on stderr, exit code 3 (never confused with a verdict)."""


BASELINE_FORMAT = "skill-auditor-baseline"
BASELINE_VERSION = 1
BASELINE_MAX_BYTES = 5_000_000
BASELINE_MAX_ENTRIES = 20_000
LIST_LIMIT = 50


def clip(text: str, n: int = 200) -> str:
    text = "".join(ch if ch.isprintable() else " " for ch in text.strip())
    return text if len(text) <= n else text[: n - 1] + "…"


def lower_sev(sev: str, steps: int = 1) -> str:
    return SEV_BY_LEVEL[max(SEV_ORDER[sev] - steps, 1)]


@dataclass
class Finding:
    severity: str
    rule: str
    category: str
    file: str
    line: int
    message: str
    evidence: str = ""
    changed_since_baseline: bool = False

    def as_dict(self):
        return self.__dict__.copy()


@dataclass
class Auditor:
    root: Path
    only: Path | None = None
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    total_bytes: int = 0
    kinds: dict = field(default_factory=lambda: {"code": 0, "doc": 0, "config": 0, "text": 0, "binary": 0})
    urls: dict = field(default_factory=dict)
    file_rules: dict = field(default_factory=dict)  # file -> set(rule ids) for correlation
    code_files: set = field(default_factory=set)
    skipped: list = field(default_factory=list)
    mcp_servers: list = field(default_factory=list)

    def add(self, sev, rule, cat, file, line, msg, evidence=""):
        self.findings.append(Finding(sev, rule, cat, file, line, msg, clip(evidence)))

    # ---------------------------------------------------------------- traversal
    def iter_files(self):
        if self.only is not None:
            yield self.only
            return
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            dp = Path(dirpath)
            keep = []
            for d in sorted(dirnames):
                full = dp / d
                rel = str(full.relative_to(self.root))
                if full.is_symlink():
                    self.check_symlink(full, rel)
                    continue
                if d == ".git":
                    self.skipped.append(rel + " (.git directory skipped)")
                    continue
                if d in VENDORED_DIRS:
                    self.add("medium", "VENDORED_DIR", "supply-chain", rel, 0,
                             "Bundled dependency or cache directory: content cannot be reviewed", d)
                    self.skipped.append(rel + " (not scanned)")
                    continue
                if d.startswith(".") and d not in {".github"}:
                    self.add("low", "HIDDEN_DIR", "structure", rel, 0, "Hidden directory inside the skill", d)
                keep.append(d)
            dirnames[:] = keep
            for f in sorted(filenames):
                yield dp / f

    def check_symlink(self, path: Path, rel: str):
        try:
            target = os.path.realpath(path)
        except OSError:
            target = "?"
        inside = target.startswith(str(self.root.resolve()) + os.sep)
        self.add("high" if not inside else "low", "SYMLINK", "structure", rel, 0,
                 "Symbolic link" + (" pointing outside the skill" if not inside else ""),
                 f"-> {target}")

    # ---------------------------------------------------------------- analysis
    def run(self):
        for path in self.iter_files():
            rel = str(path.relative_to(self.root)) if self.only is None else path.name
            if path.is_symlink():
                self.check_symlink(path, rel)
                continue
            try:
                st = path.stat()
                if st.st_size > MAX_FILE_BYTES:
                    self.add("medium", "FILE_TOO_BIG", "structure", rel, 0,
                             f"File too large to scan ({st.st_size // 1024} KB)", rel)
                    self.skipped.append(rel + " (too large)")
                    continue
                data = path.read_bytes()
            except OSError as exc:
                self.skipped.append(f"{rel} (read error: {exc})")
                continue
            self.files_scanned += 1
            self.total_bytes += len(data)
            if st.st_mode & stat.S_IXUSR:
                self.add("info", "EXECUTABLE_BIT", "structure", rel, 0, "File with the execute permission bit set", "")
            self.analyze_file(path, rel, data)

        self.correlate()
        self.check_skill_md()
        self.dedupe()

    def dedupe(self):
        """The same (rule, file, line) is reported only once, with the highest severity."""
        best: dict[tuple, Finding] = {}
        for f in self.findings:
            key = (f.rule, f.file, f.line) if f.line else (f.rule, f.file, f.line, f.message)
            cur = best.get(key)
            if cur is None or SEV_ORDER[f.severity] > SEV_ORDER[cur.severity]:
                if cur is not None and "HTML comment" in cur.message and "HTML comment" not in f.message:
                    f.message = cur.message
                best[key] = f
        self.findings = list(best.values())

    def analyze_file(self, path: Path, rel: str, data: bytes):
        ext = path.suffix.lower()
        name = path.name.lower()
        if ext in IGNORE_BINARY_EXT:
            self.kinds["binary"] += 1
            return
        for magic, label in BINARY_MAGIC:
            if data.startswith(magic) and ext not in DOC_EXT:
                self.kinds["binary"] += 1
                self.add("high", "BINARY_EXEC", "opaque-binary", rel, 0,
                         f"Binary executable ({label}): cannot be audited with static analysis", rel)
                return
        if ext in OPAQUE_EXT:
            self.kinds["binary"] += 1
            self.add("high", "OPAQUE_FILE", "opaque-binary", rel, 0,
                     "Opaque file (binary, compressed or compiled): cannot be reviewed", rel)
            return
        if b"\x00" in data[:4096]:
            self.kinds["binary"] += 1
            self.add("medium", "BINARY_UNKNOWN", "opaque-binary", rel, 0,
                     "Binary file of unknown type", rel)
            return

        text = data.decode("utf-8", errors="replace")
        if ext in CODE_EXT or data.startswith(b"#!"):
            kind = "code"
        elif ext in DOC_EXT:
            kind = "doc"
        elif ext in CONFIG_EXT or name.startswith(".env"):
            kind = "config"
        else:
            kind = "text"
        self.kinds[kind] += 1
        if kind == "code":
            self.code_files.add(rel)

        self.scan_lines(rel, text, kind)
        self.scan_hidden_unicode(rel, text)
        self.collect_urls(rel, text)
        if kind in ("doc", "text"):
            self.scan_html_comments(rel, text)
            self.scan_deceptive_links(rel, text)
        if ext == ".svg" or "<script" in text.lower() and ext in {".svg", ".html", ".htm"}:
            if "<script" in text.lower():
                self.add("medium", "SCRIPT_IN_MARKUP", "execution", rel, 0,
                         "Content with <script> tags", rel)
        if name == "package.json":
            self.check_package_json(rel, text)
        if name in {".mcp.json", "mcp.json", "claude_desktop_config.json"} or name.endswith(".mcp.json") \
                or '"mcpServers"' in text:
            self.check_mcp_config(rel, text)

    def scan_lines(self, rel: str, text: str, kind: str):
        counts: dict[str, int] = {}
        ids: set[str] = set()
        for lineno, raw in enumerate(text.splitlines(), start=1):
            line = raw[:MAX_LINE_SCAN]
            if not line.strip():
                continue
            for rule in RULES:
                if rule.scope == "code" and kind not in ("code", "config"):
                    continue
                if not rule.pattern.search(line):
                    continue
                ids.add(rule.id)
                counts[rule.id] = counts.get(rule.id, 0) + 1
                if counts[rule.id] > MAX_PER_RULE_PER_FILE:
                    continue
                sev = rule.sev
                note = ""
                # In SKILL.md the text is the instruction the agent will obey: never downgraded.
                is_skill_md = rel.replace("\\", "/") == "SKILL.md"
                if kind in ("doc", "text") and rule.cat != "prompt-injection" and not is_skill_md:
                    sev = lower_sev(sev)
                    note = " (mentioned in documentation)"
                self.add(sev, rule.id, rule.cat, rel, lineno, rule.msg + note, line)
        for rid, n in counts.items():
            if n > MAX_PER_RULE_PER_FILE:
                self.add("info", rid, "summary", rel, 0,
                         f"{n - MAX_PER_RULE_PER_FILE} additional {rid} matches not shown", "")
        self.file_rules[rel] = ids

    def scan_hidden_unicode(self, rel: str, text: str):
        for regex, sev, rid, msg in (
            (TAG_CHARS, "critical", "UNICODE_TAGS",
             "Invisible Unicode 'tag' characters (can hide entire instructions)"),
            (BIDI_CHARS, "high", "UNICODE_BIDI",
             "Bidirectional control characters (code looks different from how it is interpreted)"),
        ):
            m = list(regex.finditer(text))
            if m:
                line = text.count("\n", 0, m[0].start()) + 1
                self.add(sev, rid, "concealment", rel, line, f"{msg}: {len(m)} occurrence(s)", "")
        zw = [m for m in ZERO_WIDTH.finditer(text) if not (m.start() == 0 and m.group() == "\ufeff")]
        if zw:
            line = text.count("\n", 0, zw[0].start()) + 1
            sev = "low" if len(zw) <= 3 else "medium"
            self.add(sev, "UNICODE_ZERO_WIDTH", "concealment", rel, line,
                     f"Invisible zero-width characters: {len(zw)} occurrence(s)", "")

    def scan_html_comments(self, rel: str, text: str):
        for m in HTML_COMMENT.finditer(text):
            body = " ".join(m.group(1).split())
            if not body:
                continue
            line = text.count("\n", 0, m.start()) + 1
            hit = False
            for rule in INJECTION_RULES:
                if rule.id == "INJ_HIDDEN_CMD":
                    continue
                if rule.pattern.search(body):
                    self.add("high", rule.id, "prompt-injection", rel, line,
                             rule.msg + " (inside a hidden HTML comment)", body)
                    hit = True
            if not hit:
                self.add("medium", "HTML_COMMENT", "concealment", rel, line,
                         "Hidden HTML comment in markdown: read it in full", body)

    def scan_deceptive_links(self, rel: str, text: str):
        for m in MD_DECEPTIVE_LINK.finditer(text):
            shown = re.sub(r"^https?://", "", m.group(1), flags=re.I).split("/")[0].lower()
            real = re.sub(r"^https?://", "", m.group(2), flags=re.I).split("/")[0].lower()
            shown_root = ".".join(shown.split(".")[-2:])
            real_root = ".".join(real.split(".")[-2:])
            if shown_root != real_root:
                line = text.count("\n", 0, m.start()) + 1
                self.add("medium", "DECEPTIVE_LINK", "concealment", rel, line,
                         "Link whose text shows one domain and points to another", m.group(0))

    def collect_urls(self, rel: str, text: str):
        for m in URL_RE.finditer(text):
            url = m.group(0).rstrip(".,;:")
            host = re.sub(r"^https?://", "", url, flags=re.I).split("/")[0].split("@")[-1].split(":")[0].lower()
            self.urls.setdefault(host, set()).add(rel)
            if url.lower().startswith("http://") and host not in {"localhost", "127.0.0.1"}:
                line = text.count("\n", 0, m.start()) + 1
                self.add("low", "HTTP_NO_TLS", "network", rel, line, "URL without TLS (http://)", url)

    # ---------------------------------------------------------------- specific checks
    def check_package_json(self, rel: str, text: str):
        try:
            pkg = json.loads(text)
        except ValueError:
            self.add("low", "BAD_JSON", "structure", rel, 0, "package.json is not valid JSON", "")
            return
        scripts = pkg.get("scripts", {}) if isinstance(pkg, dict) else {}
        for hook in ("preinstall", "install", "postinstall", "prepare"):
            if hook in scripts:
                self.add("high", "NPM_LIFECYCLE", "supply-chain", rel, 0,
                         f"Lifecycle script '{hook}': runs on install", f"{hook}: {scripts[hook]}")

    def check_mcp_config(self, rel: str, text: str):
        try:
            cfg = json.loads(text)
        except ValueError:
            self.add("low", "BAD_JSON", "structure", rel, 0, "MCP configuration is not valid JSON", "")
            return
        servers = cfg.get("mcpServers", {}) if isinstance(cfg, dict) else {}
        if not isinstance(servers, dict):
            return
        runners = {"npx", "uvx", "bunx", "pipx", "docker", "podman"}
        shells = {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}
        for sname, srv in servers.items():
            if not isinstance(srv, dict):
                continue
            cmd = str(srv.get("command", ""))
            args = [str(a) for a in srv.get("args", []) if isinstance(a, (str, int, float))]
            url = str(srv.get("url", ""))
            env = srv.get("env", {}) if isinstance(srv.get("env"), dict) else {}
            self.mcp_servers.append({"file": rel, "name": sname, "command": cmd, "args": args, "url": url,
                                     "env_keys": sorted(env)})
            base = os.path.basename(cmd).lower()
            desc = f"{cmd} {' '.join(args)}".strip() or url
            self.add("info", "MCP_SERVER", "mcp", rel, 0, f"MCP server '{sname}'", desc)
            if base in shells:
                self.add("high", "MCP_SHELL", "mcp", rel, 0,
                         f"MCP server '{sname}' is launched through a shell", desc)
            if base in runners:
                pkgs = [a for a in args if not a.startswith("-")]
                pinned = any(re.search(r"@[\d]|==[\d]|:[\d]|@sha256", a) for a in pkgs)
                if not pinned:
                    self.add("medium", "MCP_UNPINNED", "mcp", rel, 0,
                             f"'{sname}' downloads and runs a package without a pinned version", desc)
                if "-y" in args or "--yes" in args:
                    self.add("low", "MCP_AUTO_YES", "mcp", rel, 0,
                             f"'{sname}' accepts installation automatically (-y)", desc)
            if url.lower().startswith("http://"):
                self.add("high", "MCP_NO_TLS", "mcp", rel, 0,
                         f"Remote MCP server '{sname}' uses unencrypted http://", url)
            for k, v in env.items():
                if re.search(r"(KEY|TOKEN|SECRET|PASSWORD)", str(k), re.I) and str(v) and not str(v).startswith("${"):
                    self.add("medium", "MCP_PLAIN_SECRET", "mcp", rel, 0,
                             f"Plaintext secret in the configuration of '{sname}' ({k})", "")

    def check_skill_md(self):
        if self.only is not None and self.only.name != "SKILL.md":
            return
        skill_md = (self.only if self.only else self.root / "SKILL.md")
        if not skill_md.is_file():
            self.add("high", "NO_SKILL_MD", "structure", "SKILL.md", 0,
                     "No SKILL.md at the root: not a valid skill or badly packaged", "")
            return
        text = skill_md.read_text(encoding="utf-8", errors="replace")
        m = re.match(r"^\ufeff?---\s*\n(.*?)\n---\s*(\n|$)", text, re.S)
        if not m:
            self.add("high", "NO_FRONTMATTER", "structure", "SKILL.md", 1,
                     "SKILL.md without YAML frontmatter (name/description)", "")
            return
        fm = m.group(1)
        fields: dict[str, str] = {}
        current = None
        for line in fm.splitlines():
            km = re.match(r"^([A-Za-z0-9_-]+)\s*:\s*(.*)$", line)
            if km:
                current = km.group(1).lower()
                fields[current] = km.group(2).strip()
            elif current and (line.startswith((" ", "\t", "-"))):
                fields[current] += " " + line.strip()
        name = fields.get("name", "").strip("\"' ")
        desc = fields.get("description", "").strip("\"' ")
        if not name or not re.fullmatch(r"[a-z0-9-]{1,64}", name):
            self.add("medium", "BAD_NAME", "structure", "SKILL.md", 1,
                     "Name missing or badly formatted (lowercase, digits and hyphens, max 64)", name)
        elif re.search(r"anthropic|claude", name):
            self.add("medium", "RESERVED_NAME", "impersonation", "SKILL.md", 1,
                     "Name contains a reserved term (possible impersonation)", name)
        if not desc:
            self.add("medium", "NO_DESCRIPTION", "structure", "SKILL.md", 1, "Description missing", "")
        else:
            if len(desc) > 1024:
                self.add("low", "LONG_DESCRIPTION", "structure", "SKILL.md", 1,
                         f"Description is {len(desc)} characters long (usual limit: 1024)", "")
            if re.search(r"[<>]", desc):
                self.add("medium", "ANGLE_IN_DESCRIPTION", "structure", "SKILL.md", 1,
                         "Description contains < or > (possible markup or injection)", desc)
            if re.search(r"\b(always|every|any|all)\b[^.]{0,30}\b(task|conversation|request|prompt)s?\b|"
                         r"\b(siempre|cualquier|todas?\s+las)\b[^.]{0,30}\b(tarea|conversaci\w+|petici\w+)s?\b",
                         desc, re.I):
                self.add("medium", "FORCED_TRIGGER", "agent-tampering", "SKILL.md", 1,
                         "Description that forces activation on any task", desc)
        tools = fields.get("allowed-tools", "")
        if tools:
            if re.search(r"(^|[\s,\[\"'])Bash(?!\()(?=[\s,\]\"']|$)|Bash\(\s*\*\s*\)|(^|[\s,\[])\*($|[\s,\]])", tools):
                self.add("high", "TOOLS_UNRESTRICTED", "permissions", "SKILL.md", 1,
                         "Pre-authorizes tools without restriction (full shell or wildcard)", tools)
            elif re.search(r"Bash\(", tools):
                self.add("low", "TOOLS_BASH_SCOPED", "permissions", "SKILL.md", 1,
                         "Pre-authorizes specific shell commands: check they are the minimum needed", tools)
            if re.search(r"WebFetch|WebSearch", tools) and re.search(r"Bash|Write|Edit", tools):
                self.add("medium", "TOOLS_COMBO", "permissions", "SKILL.md", 1,
                         "Combines web access with write or shell access (sensitive combination)", tools)

    # ---------------------------------------------------------------- correlation
    def correlate(self):
        cred = {"SENSITIVE_PATH", "ENV_DUMP"}
        net = {"NETWORK", "EXFIL_SERVICE"}
        cred_files, net_files = [], []
        for rel, ids in self.file_rules.items():
            if rel not in self.code_files:
                continue
            if ids & cred and ids & net:
                self.add("critical", "EXFIL_COMBO", "exfiltration", rel, 0,
                         "The same file accesses credentials or environment variables and makes outbound "
                         "network calls: possible exfiltration (confirm the data flow by hand)", "")
            if ids & {"B64_DECODE", "LONG_BLOB"} and "DYN_EXEC" in ids:
                self.add("critical", "OBFUSCATED_EXEC", "obfuscation", rel, 0,
                         "Decodes obfuscated content and executes it dynamically", "")
            if ids & cred:
                cred_files.append(rel)
            if ids & net:
                net_files.append(rel)
        already = {f.file for f in self.findings if f.rule == "EXFIL_COMBO"}
        if cred_files and net_files and not (set(cred_files) | set(net_files)) <= already:
            self.add("high", "EXFIL_COMBO_SKILL", "exfiltration", "(several files)", 0,
                     "The skill contains code that accesses credentials and code that makes outbound network "
                     "calls, in different files: check whether they chain together",
                     f"credentials: {', '.join(cred_files[:3])} | network: {', '.join(net_files[:3])}")

    # ---------------------------------------------------------------- result
    def summary(self):
        counts = {k: 0 for k in SEV_ORDER}
        for f in self.findings:
            counts[f.severity] += 1
        if counts["critical"]:
            verdict, code = "DO NOT INSTALL", 2
        elif counts["high"] or counts["medium"] >= 5:
            verdict, code = "REVIEW IN DEPTH", 1
        elif counts["medium"]:
            verdict, code = "LOW RISK (check the warnings)", 0
        else:
            verdict, code = "NO RELEVANT FINDINGS", 0
        return counts, verdict, code


def extract_zip_safely(zpath: Path, dest: Path):
    with zipfile.ZipFile(zpath) as z:
        infos = z.infolist()
        if len(infos) > ZIP_MAX_FILES:
            raise ScanError(f"The archive has too many files ({len(infos)}).")
        if sum(i.file_size for i in infos) > ZIP_MAX_BYTES:
            raise ScanError("The archive is too large once extracted.")
        dest_resolved = dest.resolve()
        for info in infos:
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ScanError(f"The archive contains a symbolic link ({info.filename}): rejected.")
            target = (dest / info.filename).resolve()
            if not str(target).startswith(str(dest_resolved) + os.sep) and target != dest_resolved:
                raise ScanError(f"Unsafe path in the archive ({info.filename}): rejected.")
        z.extractall(dest)
    entries = [p for p in dest.iterdir()]
    if len(entries) == 1 and entries[0].is_dir() and not (dest / "SKILL.md").exists():
        return entries[0]
    return dest


# ---------------------------------------------------------------- baseline (re-audit on change)
def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(root: Path, only: Path | None, exclude: set) -> dict:
    """SHA-256 of every file under root (symlinks are recorded, never followed; .git is skipped).

    Only reads bytes: nothing from the target is executed or imported."""
    files: dict[str, str] = {}

    def add(p: Path, rel: str):
        if p.resolve() in exclude:
            return
        if p.is_symlink():
            files[rel] = "symlink->" + os.readlink(p)
        else:
            try:
                files[rel] = sha256_file(p)
            except OSError as exc:
                files[rel] = f"unreadable:{exc.__class__.__name__}"

    if only is not None:
        add(only, only.name)
        return files
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dp = Path(dirpath)
        keep = []
        for d in sorted(dirnames):
            full = dp / d
            if full.is_symlink():
                add(full, full.relative_to(root).as_posix())
            elif d != ".git":
                keep.append(d)
        dirnames[:] = keep
        for f in sorted(filenames):
            full = dp / f
            add(full, full.relative_to(root).as_posix())
    return files


def tree_hash(files: dict) -> str:
    h = hashlib.sha256()
    for rel in sorted(files):
        h.update(f"{rel}\0{files[rel]}\n".encode("utf-8", errors="replace"))
    return h.hexdigest()


def load_baseline(path: Path) -> dict:
    """A baseline file is untrusted input too: parsed as JSON only, validated, never evaluated."""
    try:
        if path.stat().st_size > BASELINE_MAX_BYTES:
            raise ScanError(f"Baseline file is too large: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ScanError(f"Cannot read baseline {path}: {exc.__class__.__name__}")
    except ValueError:
        raise ScanError(f"Baseline is not valid JSON: {path}")
    if not isinstance(data, dict) or data.get("format") != BASELINE_FORMAT:
        raise ScanError(f"Not a Skill Auditor baseline file: {path}")
    if data.get("version") != BASELINE_VERSION:
        raise ScanError(f"Unsupported baseline version {data.get('version')!r} (expected {BASELINE_VERSION})")
    files = data.get("files")
    if not isinstance(files, dict) or len(files) > BASELINE_MAX_ENTRIES or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in files.items()):
        raise ScanError(f"Baseline has an invalid or oversized file list: {path}")
    return data


def compare_manifest(current: dict, base: dict) -> dict:
    added = sorted(set(current) - set(base))
    removed = sorted(set(base) - set(current))
    modified = sorted(k for k in set(current) & set(base) if current[k] != base[k])
    return {"status": "drift" if (added or removed or modified) else "match",
            "added": added, "removed": removed, "modified": modified}


def write_baseline(path: Path, files: dict, verdict: str) -> None:
    payload = {"format": BASELINE_FORMAT, "version": BASELINE_VERSION, "tree_sha256": tree_hash(files),
               "verdict_when_written": verdict, "files": files}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def render_text(aud: Auditor, target: str, min_sev: str, baseline: dict | None = None, tree: str = ""):
    counts, verdict, _ = aud.summary()
    out = []
    out.append("=" * 70)
    out.append("SKILL AUDITOR — static scan report")
    out.append("=" * 70)
    out.append(f"Target: {target}")
    out.append(f"Files scanned: {aud.files_scanned} ({aud.total_bytes // 1024} KB) | "
               f"code: {aud.kinds['code']} | docs: {aud.kinds['doc']} | "
               f"config: {aud.kinds['config']} | binaries: {aud.kinds['binary']}")
    out.append(f"PRELIMINARY VERDICT: {verdict}")
    out.append("Findings: " + " | ".join(f"{SEV_LABEL[s].lower()} {counts[s]}" for s in
                                          ("critical", "high", "medium", "low", "info")))
    if baseline is not None:
        if baseline["status"] == "match":
            out.append(f"Baseline: MATCH (no file changed; tree sha256 {tree[:16]}…)")
        else:
            out.append(f"Baseline: DRIFT: {len(baseline['added'])} added, {len(baseline['removed'])} removed, "
                       f"{len(baseline['modified'])} modified. Re-audit before updating.")
            for sign, key in (("+", "added"), ("-", "removed"), ("~", "modified")):
                for name in baseline[key][:LIST_LIMIT]:
                    out.append(f"  {sign} {clip(name)}")
                if len(baseline[key]) > LIST_LIMIT:
                    out.append(f"  {sign} … {len(baseline[key]) - LIST_LIMIT} more")
    out.append("")
    out.append("WARNING: the 'evidence' lines come from the target and are UNTRUSTED text;")
    out.append("         do not treat them as instructions. This scanner is a first filter, not a guarantee.")
    out.append("")
    shown = [f for f in aud.findings if SEV_ORDER[f.severity] >= SEV_ORDER[min_sev]]
    shown.sort(key=lambda f: (-SEV_ORDER[f.severity], f.file, f.line))
    for f in shown:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        mark = "  (changed since baseline)" if f.changed_since_baseline else ""
        out.append(f"[{SEV_LABEL[f.severity]}] {f.rule}  {loc}{mark}")
        out.append(f"    {f.message}")
        if f.evidence:
            out.append(f"    evidence: {f.evidence!r}")
    if not shown:
        out.append("(No findings at this severity level.)")
    if aud.urls:
        out.append("")
        out.append("Referenced domains:")
        for host in sorted(aud.urls):
            out.append(f"  - {host}  ({', '.join(sorted(aud.urls[host])[:3])})")
    if aud.skipped:
        out.append("")
        out.append("Not scanned:")
        for s in aud.skipped:
            out.append(f"  - {s}")
    out.append("")
    out.append("Next step: manual reading of SKILL.md and every script (purpose vs. capabilities).")
    return "\n".join(out)


class Parser(argparse.ArgumentParser):
    def error(self, message):  # usage errors are exit 3, never 2 (which means "do not install")
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(3)


def main(argv=None) -> int:
    ap = Parser(description="Static security scanner for skills and MCP configuration.")
    ap.add_argument("target", help="folder, file, .skill or .zip to analyze")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--out", help="also save the JSON report to this file")
    ap.add_argument("-v", "--verbose", action="store_true", help="include informational findings")
    ap.add_argument("--write-baseline", metavar="FILE",
                    help="record a SHA-256 manifest of the target (a baseline records content, it does not endorse it)")
    ap.add_argument("--baseline", metavar="FILE",
                    help="compare the target with a baseline; exit 4 if any file was added, removed or modified")
    args = ap.parse_args(argv)
    if args.baseline and args.write_baseline:
        ap.error("--baseline and --write-baseline cannot be used together (re-baselining must be a deliberate step)")

    target = Path(args.target)
    if not target.exists():
        print(f"Does not exist: {target}", file=sys.stderr)
        return 3

    base = None
    if args.baseline:
        try:
            base = load_baseline(Path(args.baseline))
        except ScanError as exc:
            print(str(exc), file=sys.stderr)
            return 3
    exclude = {Path(p).resolve() for p in (args.baseline, args.write_baseline) if p}

    tmp = None
    try:
        if target.is_file() and target.suffix.lower() in {".zip", ".skill"}:
            tmp = Path(tempfile.mkdtemp(prefix="skill-audit-"))
            root = extract_zip_safely(target, tmp)
            aud = Auditor(root=root)
        elif target.is_dir():
            aud = Auditor(root=target.resolve())
        else:
            aud = Auditor(root=target.resolve().parent, only=target.resolve())
        aud.run()
        manifest = build_manifest(aud.root, aud.only, exclude)
    except ScanError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)

    counts, verdict, code = aud.summary()
    tree = tree_hash(manifest)
    baseline_info = None
    if base is not None:
        baseline_info = compare_manifest(manifest, base["files"])
        baseline_info["baseline_tree_sha256"] = str(base.get("tree_sha256", ""))
        changed = set(baseline_info["added"]) | set(baseline_info["modified"])
        for f in aud.findings:
            f.changed_since_baseline = f.file in changed
        if baseline_info["status"] == "drift" and code != 2:
            code = 4
    if args.write_baseline:
        try:
            write_baseline(Path(args.write_baseline), manifest, verdict)
        except OSError as exc:
            print(f"Cannot write baseline {args.write_baseline}: {exc.__class__.__name__}", file=sys.stderr)
            return 3
        print(f"Baseline written to {args.write_baseline} ({len(manifest)} files, tree sha256 {tree[:16]}…)",
              file=sys.stderr)
        if code == 2:
            print("Warning: this target's verdict is DO NOT INSTALL. A baseline records content; it does not endorse it.",
                  file=sys.stderr)
    payload = {
        "target": str(target),
        "verdict": verdict,
        "counts": counts,
        "files_scanned": aud.files_scanned,
        "kinds": aud.kinds,
        "findings": [f.as_dict() for f in sorted(
            aud.findings, key=lambda f: (-SEV_ORDER[f.severity], f.file, f.line))],
        "domains": {h: sorted(v) for h, v in sorted(aud.urls.items())},
        "mcp_servers": aud.mcp_servers,
        "skipped": aud.skipped,
        "tree_sha256": tree,
        "files_hashed": len(manifest),
        "baseline": baseline_info,
        "note": "Evidence = untrusted text from the target. Static analysis: not a guarantee.",
    }
    if args.out:
        Path(args.out).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(render_text(aud, str(target), "info" if args.verbose else "low", baseline_info, tree))
    return code


if __name__ == "__main__":
    sys.exit(main())
