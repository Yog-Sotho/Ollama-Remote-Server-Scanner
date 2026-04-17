## 2026-04-03 - [Security Enhancement] Truncating Sensitive Log Data
**Vulnerability:** Accidental leakage of full secrets (API keys, tokens) in logs and error messages when the scanner is inadvertently run against non-IP target lists containing sensitive data.
**Learning:** Initial truncation (32 chars) was insufficient as it could truncate valid IPv6 addresses and still leak a significant portion of a secret.
**Prevention:** Use a dedicated `safe_display` helper function to truncate strings longer than 48 characters, showing only the first 8 characters and a truncation notice. This protects secrets while preserving the full length of valid network identifiers.

## 2026-04-04 - [Security Enhancement] Terminal/ANSI Injection Protection
**Vulnerability:** Malicious remote servers could return ANSI escape sequences or control characters (like `\r`) in model names or prompts, allowing terminal manipulation or deception (e.g., overwriting lines, hiding info).
**Learning:** Sanitizing untrusted server data is critical for CLI tools. Stripping `\r` along with other non-printable characters (except `\n` and `\t`) prevents line-overwrite attacks.
**Prevention:** Implement a `sanitize_text` function with a module-level compiled regex to strip ANSI escapes and non-printable characters from all data fetched from remote endpoints before display or storage.

## 2026-04-14 - [Security Enhancement] SSRF Protection via Redirect Disabling
**Vulnerability:** A malicious remote server could return an HTTP 3xx redirect to an internal or sensitive service (e.g., cloud metadata endpoints, internal APIs), potentially coercing the scanner into probing unauthorized targets.
**Learning:** Default `aiohttp` behavior is to follow redirects. For a network scanner probing untrusted endpoints, this behavior must be explicitly disabled to prevent Server-Side Request Forgery (SSRF).
**Prevention:** Set `allow_redirects=False` in all `aiohttp` request calls (`session.get`, `session.post`) that target remote servers. This ensures the scanner only interacts with the explicitly targeted host and port.

## 2026-04-17 - [Security Enhancement] Robust Public Network Detection
**Vulnerability:** Accidental scanning of public internet-routable IP addresses. Previous checks used `not is_private`, which missed ranges like CGNAT (100.64.0.0/10) that are technically not private but also not global.
**Learning:** The `ipaddress` module's `.is_global` property is the most reliable way to identify addresses routable on the public internet, as it accounts for various reserved and non-global ranges beyond just RFC 1918.
**Prevention:** Use `ip_address.is_global` (or `ip_network.is_global`) to trigger security warnings when a user targets public network ranges. Ensure this check is applied consistently across all input formats (CIDR, hyphenated ranges, and single IPs).
