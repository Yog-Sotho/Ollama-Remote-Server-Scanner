## 2026-04-03 - [Security Enhancement] Truncating Sensitive Log Data
**Vulnerability:** Accidental leakage of full secrets (API keys, tokens) in logs and error messages when the scanner is inadvertently run against non-IP target lists containing sensitive data.
**Learning:** Initial truncation (32 chars) was insufficient as it could truncate valid IPv6 addresses and still leak a significant portion of a secret.
**Prevention:** Use a dedicated `safe_display` helper function to truncate strings longer than 48 characters, showing only the first 8 characters and a truncation notice. This protects secrets while preserving the full length of valid network identifiers.

## 2026-04-04 - [Security Enhancement] Terminal/ANSI Injection Protection
**Vulnerability:** Malicious remote servers could return ANSI escape sequences or control characters (like `\r`) in model names or prompts, allowing terminal manipulation or deception (e.g., overwriting lines, hiding info).
**Learning:** Sanitizing untrusted server data is critical for CLI tools. Stripping `\r` along with other non-printable characters (except `\n` and `\t`) prevents line-overwrite attacks.
**Prevention:** Implement a `sanitize_text` function with a module-level compiled regex to strip ANSI escapes and non-printable characters from all data fetched from remote endpoints before display or storage.
