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

## 2026-05-20 - [Security Enhancement] Resource Exhaustion Protection
**Vulnerability:** A malicious or misconfigured remote LLM server could return an extremely large number of models or processes, potentially causing memory exhaustion (OOM) or excessive processing time in the scanner.
**Learning:** Network scanners interacting with untrusted endpoints must enforce logical limits on the amount of data processed from any single response, even after the raw payload is received.
**Prevention:** Implement a hard cap (e.g., 50 items) on all lists retrieved from remote APIs (like /api/tags or /api/ps) to ensure stable performance and resource usage regardless of the server's response size.

## 2026-05-22 - [Security Enhancement] Resource Exhaustion via Malicious String Lengths
**Vulnerability:** Untrusted data from remote servers could contain extremely long strings (model names, prompts, etc.), leading to memory exhaustion (DoS) or terminal pollution.
**Learning:** Limiting the number of items in a response is only half the battle; the size of individual fields must also be capped to ensure total response size and processing overhead remain bounded.
**Prevention:** Pass a `max_len` parameter to all sanitization routines for untrusted data, enforcing strict limits (e.g., 256 for identifiers, 1024 for content) at the point of ingestion.

## 2026-04-20 - [Security Enhancement] Robust Public IP Detection
**Vulnerability:** Scanners may inadvertently target public internet ranges when users provide single IPs or hyphenated ranges if warning logic only checks CIDR blocks using simple 'not private' filters.
**Learning:** Manual exclusion filters (like `not (is_private or is_loopback)`) often miss edge cases like multicast, link-local, or reserved ranges. Python's `ipaddress` module provides `.is_global`, which more accurately identifies internet-routable addresses.
**Prevention:** Use `network.is_global` or `address.is_global` to determine if a target is on the public internet. Ensure this check is applied to all input formats, including single addresses and hyphenated ranges, to maximize user awareness and prevent accidental unauthorized scanning.
