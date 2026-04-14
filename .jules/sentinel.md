## 2026-04-03 - [Security Enhancement] Truncating Sensitive Log Data
**Vulnerability:** Accidental leakage of full secrets (API keys, tokens) in logs and error messages when the scanner is inadvertently run against non-IP target lists containing sensitive data.
**Learning:** Initial truncation (32 chars) was insufficient as it could truncate valid IPv6 addresses and still leak a significant portion of a secret.
**Prevention:** Use a dedicated `safe_display` helper function to truncate strings longer than 48 characters, showing only the first 8 characters and a truncation notice. This protects secrets while preserving the full length of valid network identifiers.

## 2026-04-04 - [Security Enhancement] Terminal/ANSI Injection Protection
**Vulnerability:** Malicious remote servers could return ANSI escape sequences or control characters (like `\r`) in model names or prompts, allowing terminal manipulation or deception (e.g., overwriting lines, hiding info).
**Learning:** Sanitizing untrusted server data is critical for CLI tools. Stripping `\r` along with other non-printable characters (except `\n` and `\t`) prevents line-overwrite attacks.
**Prevention:** Implement a `sanitize_text` function with a module-level compiled regex to strip ANSI escapes and non-printable characters from all data fetched from remote endpoints before display or storage.

## 2026-04-05 - [Security Enhancement] Disabling HTTP Redirects (SSRF Protection)
**Vulnerability:** A network scanner following HTTP redirects could be coerced into probing internal services or sensitive local endpoints (SSRF) if a target server responds with a 3xx redirect to a private IP or loopback address.
**Learning:** For discovery tools, following redirects is rarely necessary and introduces significant security risk. Disabling them at the request level is a simple and effective defense-in-depth measure.
**Prevention:** Always set `allow_redirects=False` in `aiohttp` (or equivalent) when performing automated scanning of remote targets to ensure the probe remains focused on the intended IP and port.
## 2026-04-05 - [Security Enhancement] SSRF Mitigation and Robust Network Validation
**Vulnerability:** Malicious remote servers could use HTTP redirects to coerce the scanner into performing SSRF against internal resources (e.g., 169.254.169.254). Additionally, manual RFC 1918 checks were incomplete, missing loopback and link-local ranges.
**Learning:** Default HTTP client behavior (following redirects) is dangerous in security tools that probe untrusted endpoints. Using the built-in `ipaddress.is_private` is more reliable than manual subnet checks.
**Prevention:** Always set `allow_redirects=False` when probing unknown remote services to prevent SSRF via redirection. Leverage standard library `is_private` properties for comprehensive network classification.
