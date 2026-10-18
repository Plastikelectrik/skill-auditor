# MCP server checklist

An MCP server is either a program that runs on the user's machine (local) or a service that receives their data (remote). Installing one amounts to granting a permanent permission. Go through every point before recommending its use.

## 1. Origin and reputation

- Who publishes it? Is it the service provider itself or a third party?
- Does the repository have history, maintenance and code review, or is it recent and inactive?
- Does the name resemble a better-known one? (typosquatting)

## 2. What gets executed (local servers)

- **Command:** `npx`, `uvx`, `bunx`, `pipx` or `docker` download and run remote code on every start. Check that the package has a **pinned version** (`package@1.2.3`) and that it is the expected one.
- A flag like `-y` accepts the installation without asking: acceptable only with a pinned version and a known origin.
- **Shell:** commands that launch `sh -c`, `bash -c`, `cmd /c` or `powershell -Command` with long strings are a high alert.
- **Paths:** does it run a local binary you can't inspect?
- **Docker:** check volume mounts (does it mount the whole home directory?), privileged mode and host networking.

## 3. Remote connection

- The URL must use **HTTPS**. `http://` exposes data and credentials.
- The domain should be consistent with the provider. Distrust literal IPs, shorteners and temporary tunnels.
- What data is sent to the server on each call? Is there a privacy and retention policy?
- Does authentication use OAuth with limited scopes, or a long-lived key?

## 4. Credentials and environment variables

- Don't put secrets in plain text inside the configuration file if it is versioned.
- Pass only the variables the server needs; don't inherit the whole environment.
- Use credentials with the minimum scope that can be revoked (read-only if that is enough).

## 5. Scope of the tools

- List the tools it exposes. Do they include writing, deleting, sending messages, payments or running commands?
- Tools with irreversible effects should require human confirmation.
- A tool whose name or description doesn't match what it does is a sign of manipulation: read the full descriptions, because the agent reads them too and they can contain hidden instructions.

## 6. Dangerous combinations

Few permissions are serious on their own, but they are together:

- Access to local files + a network tool or a message-sending tool.
- Reading private email or documents + web browsing or code execution.
- A tool that ingests untrusted external content (web pages, emails, issues) + tools with side effects (this combination enables indirect prompt injection).

If any of these occurs, recommend splitting servers, limiting scopes or requiring confirmation on every action.

## 7. Outcome

Record in the report: the exact command and version, domains, environment variables, exposed tools, and which restrictions you recommend (pinned version, minimum scope, manual confirmation, sandbox).
