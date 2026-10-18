# Risk pattern guide

Use it to interpret the scanner's findings and for the manual review. Each section explains the signal, why it matters, and how to tell legitimate use from malicious use.

## Index

1. Remote execution and obfuscation
2. Access to credentials and sensitive data
3. Exfiltration
4. Persistence and tampering with the agent's environment
5. Excessive permissions
6. Prompt injection
7. Concealment in content (Unicode, comments, links)
8. Supply chain
9. Binaries and opaque files
10. Common false positives
11. Severity scale

---

## 1. Remote execution and obfuscation

**Signals:** downloading something and piping it straight into a shell or interpreter; `eval`/`exec` on computed content; decoding base64 or other formats and executing the result; long encoded strings; `Invoke-Expression` in PowerShell.

**Why it matters:** what gets reviewed stops being what gets executed. The real code arrives after the audit and can change at any moment.

**Legitimate vs. suspicious:** downloading an official installer in a separate step, verifying its hash and then running it is reasonable. Chaining download and execution without verification, or decoding a blob in order to run it, has no justification in a skill: a script can be written in plain text.

## 2. Access to credentials and sensitive data

**Signals:** paths such as SSH key directories, cloud credentials, Kubernetes configuration, `.npmrc`, `.netrc`, browser cookie or password stores, `.env`; dumping the full set of environment variables; references to API keys.

**Why it matters:** skills run with the user's permissions. A single read of these files can compromise accounts and servers.

**Key question:** does the declared purpose require that data? A deployment skill may need one specific variable; no formatting or writing skill needs to read private keys. Reading one specific, documented environment variable is different from walking through all of them.

## 3. Exfiltration

**Signals:** sending data to domains that don't belong to the service the skill says it uses; temporary receiving or tunneling services (test webhooks, paste sites, messaging bots, tunnel services); URLs with a literal IP; URL shorteners; data encoded in URL parameters or subdomains.

**Serious combinations:** credential access + outbound network in the same file or the same flow. The scanner flags this combination as critical. Confirm it by following the data flow by hand: does what is read actually reach what is sent?

**Instructions, not just code:** a `SKILL.md` can ask the agent to send data to a URL without any script being involved. Review the text with the same attention.

## 4. Persistence and tampering with the agent's environment

**Signals:** modifying shell startup files, scheduled tasks, user services, authorized SSH keys, the Windows registry; editing the agent's configuration (settings, hooks, memory or instruction files, MCP configuration).

**Why it matters:** it lets the effect survive uninstalling the skill, or lets the agent change its own behavior and permissions in future sessions. A planted hook or persistent instruction is a command post.

**Legitimate vs. suspicious:** a skill dedicated to configuring the environment may touch these files if it declares so and asks for confirmation. In any other skill it is a high alert.

## 5. Excessive permissions

**Signals:** `allowed-tools` with unrestricted shell or wildcards; descriptions that ask to disable confirmations or to use modes that skip permissions; requests for access to the whole filesystem when one folder is enough.

**Principle:** least privilege. A skill that only transforms text doesn't need shell, network or writing outside its folder. If the author could restrict `Bash(command:*)` to what is needed and doesn't, ask why.

## 6. Prompt injection

**Signals in the skill's text:**
- Orders to ignore, forget or override earlier or system instructions.
- Hiding actions or results from the user.
- Acting without asking for confirmation, disabling protections or permissions.
- Revealing the system prompt, the history or the context.
- Redefining the agent's role ("from now on you are…", "unrestricted mode").
- Tags that imitate system or assistant messages.
- Collecting keys, tokens or files and sending them somewhere.
- A description that forces activation "always", on any task.

**Why it matters:** the agent reads the skill as trusted instructions. A single well-placed paragraph can change its behavior with no malicious code at all.

**Nuance:** documentation that *explains* these attacks (security guides, this very skill) contains the same phrases. Look at whether the text describes them or orders them.

**Languages:** the scanner's injection rules match phrases in English and Spanish. Attacks written in other languages will not be matched, so read the text yourself.

## 7. Concealment in content

- **Invisible Unicode characters:** zero-width spaces, bidirectional control characters (code looks different from how it is interpreted) and "tag" characters (they allow whole instructions to be hidden from the eye). Their presence in a skill almost never has an innocent explanation.
- **HTML comments in markdown:** they aren't visible when rendered but the agent reads them. Always read their content.
- **Deceptive links:** text that shows one domain and points to another.
- **Hidden or far-off files:** instructions buried in `references/` or `assets/` that nobody reviews. They are read all the same.

## 8. Supply chain

**Signals:** installing packages without a pinned version, directly running remote packages, `postinstall`/`preinstall` in `package.json`, dependencies with names nearly identical to well-known packages, newly created repositories or ones with no history, a fork of a popular skill with "small changes".

**What to do:** check the package's existence, age and reputation; require a pinned version or a hash; prefer dependencies already present in the environment.

## 9. Binaries and opaque files

Executables, shared libraries, compiled bytecode, native modules, WebAssembly and nested archives can't be audited with this tool. A skill is text and readable scripts by nature: the presence of binaries needs a justification, and without one, the verdict can't be better than "review in depth".

## 10. Common false positives

- Documentation that *mentions* install commands or `curl` to explain usage.
- Legitimate use of `subprocess` with fixed arguments and no shell.
- Long strings that are data (hashes, embedded fonts, base64 images for HTML).
- Mentions of `.env` in instructions like "create a `.env` file with your key".
- Security, testing or teaching skills that contain attack examples (check that they are inert and clearly labeled).

To dismiss one, note the reason in the report.

## 11. Severity scale

| Level | Meaning | Examples |
|---|---|---|
| Critical | Probable harm or clearly hostile intent | Chained download and execution; credential access with outbound network; an order to hide actions from the user; obfuscation that ends in execution; hidden tag characters |
| High | Dangerous capability with no obvious justification | Access to sensitive paths; persistence; editing the agent's configuration; unrestricted shell; exfiltration services; opaque binaries |
| Medium | Behavior that deserves review | Outbound network, package installation, `sudo`, hidden HTML comments, unpinned dependencies |
| Low | Minor warning | Isolated zero-width spaces, `http://` without TLS, incomplete metadata |
| Info | Inventory | Referenced domains, executable files |
