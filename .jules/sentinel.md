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

## 2026-05-24 - [Security Enhancement] Robust Untrusted Data Type Validation
**Vulnerability:** Malformed or malicious JSON responses from remote servers could return unexpected data types (e.g., lists where strings are expected), causing application crashes (DoS) during data processing or display.
**Learning:** Even with schema-like keys, the values in untrusted JSON responses must be explicitly type-checked. Downstream operations like string `join()` or regex substitution fail catastrophically if they receive non-string types.
**Prevention:** Always use `isinstance(data, dict)` when parsing JSON responses and ensure sanitization functions like `sanitize_text` explicitly cast input to `str` before processing. Add defensive checks for nested items within lists returned by remote APIs.

## 2026-05-26 - [Security Enhancement] Preventing Terminal Output Spoofing
**Vulnerability:** A malicious remote server could return newlines (`\n`) in model names or metadata, allowing it to inject arbitrary lines into the scanner's CLI output. This can be used to spoof status messages (e.g., "✓ Status: COMPROMISED") or hide real results.
**Learning:** Sanitizing for "printability" is insufficient for CLI tools if newlines are explicitly exempted. Untrusted data must be treated as single-line identifiers to maintain the integrity of the CLI interface.
**Prevention:** Include `\n` and `\t` in the `NON_PRINTABLE` regex. All data fetched from remote endpoints must be strictly sanitized to prevent any multi-line injection before being displayed in the terminal.

## 2026-05-26 - [Security Enhancement] Null-Safe JSON Parsing for Hostile Endpoints
**Vulnerability:** The scanner could crash (DoS) if a scanned target returns a JSON response where an expected list key (like `models`) exists but has a `null` value.
**Learning:** Python's `dict.get(key, default)` only applies the default if the key is missing. If the key exists with a `None` value, `get` returns `None`, causing subsequent operations (like slicing `[:50]`) to fail with a `TypeError`.
**Prevention:** Use the `(data.get('key') or [])` pattern when accessing expected collection fields in untrusted JSON responses. This ensures the application always has a valid iterable even if the remote server sends `null`.
## 2026-05-25 - [Security Enhancement] Robust JSON Null Handling
**Vulnerability:** A malicious remote server could return a JSON response where expected list keys (like 'models' or 'data') are present but set to `null` instead of an empty list, causing a `TypeError` and application crash in Python.
**Learning:** Python's `dict.get(key, default)` only returns the default if the key is *missing*. If the key exists with a `None` value, it returns `None`. Slicing or iterating over `None` leads to immediate crashes.
**Prevention:** Use the `(data.get('key') or [])[:limit]` pattern to ensure a list is always returned regardless of whether the key is missing or set to `null`.

## 2026-05-26 - [Security Enhancement] Bi-directional (Bidi) Character Stripping
**Vulnerability:** Malicious remote data could contain Unicode bi-directional control characters (e.g., RLO - Right-to-Left Override) to visually spoof terminal output, misleading users about the nature of discovered servers or model names.
**Learning:** Standard non-printable character filters (\x00-\x1f) often miss Unicode-specific layout control characters that can be used for "Trojan Source" style spoofing in modern terminal emulators.
**Prevention:** Extend the `sanitize_text` regex to explicitly include Unicode bidi control characters (`\u202A-\u202E` and `\u2066-\u2069`) to ensure consistent and safe visual representation of untrusted data.

## 2026-05-27 - [Security Enhancement] Type-Safe JSON Parsing for Hostile Endpoints
**Vulnerability:** The scanner could crash (DoS) if a scanned target returns a truthy non-list value (e.g., an integer or boolean) for expected list keys (like `models`), causing slicing or iteration to fail with a `TypeError`.
**Learning:** Defensive patterns like `(data.get('key') or [])` are insufficient if the value exists but is of an unexpected type. Slicing an integer or iterating over a boolean causes immediate crashes.
**Prevention:** Use explicit `isinstance(data.get('key'), list)` checks before attempting to slice or iterate over expected collection fields in untrusted JSON responses. Additionally, validate that numeric fields (like `size`) are of the expected type before performing arithmetic operations.

## 2026-06-10 - [Security Enhancement] Defensive List Item Validation
**Vulnerability:** The scanner could crash (DoS) if a remote server returned a JSON list containing non-dictionary elements, leading to `AttributeError` when the display logic attempted to access dictionary methods on the items.
**Learning:** Checking the type of the collection (e.g., `isinstance(data, list)`) is insufficient if the code assumes all elements within that collection share the same structure. Malicious actors can mix types to trigger crashes in downstream processing.
**Prevention:** Always use list comprehensions with type filters (e.g., `[m for m in items if isinstance(m, dict)]`) when parsing untrusted collections to ensure every item is of the expected type before it reaches the processing or display layers.

## 2026-05-28 - [Security Enhancement] Comprehensive Terminal Output Spoofing Protection
**Vulnerability:** A malicious remote server could return newlines (`\n`) or tabs (`\t`) in model names or metadata, allowing it to inject arbitrary lines into the scanner's CLI output to spoof status messages or hide results.
**Learning:** Initial non-printable character filters that explicitly exempt `\n` and `\t` for "safe whitespace" create a multi-line injection vector in CLI tools.
**Prevention:** Include all C0 control characters (`\x00-\x1f`) in the `NON_PRINTABLE` regex. All data fetched from remote endpoints must be strictly sanitized to single-line identifiers to maintain the integrity of the terminal interface.

## 2026-06-05 - [Security Enhancement] Advanced ANSI/OSC Injection Protection
**Vulnerability:** Insufficient ANSI escape sanitization allowed terminal injection and spoofing via Operating System Command (OSC) sequences, which could be used to manipulate terminal titles or other state.
**Learning:** Simple ANSI regexes often only cover Control Sequence Introducer (CSI) sequences, missing OSC sequences that can contain arbitrary payloads and different terminators.
**Prevention:** Use a comprehensive regex like `\x1B(?:\[[0-?]*[ -/]*[@-~]|\][0-9]*;[\s\S]*?(?:\x07|\x1B\\)|[@-_])` that accounts for OSC sequences, including their parameters and terminators like `\x07` (BEL) or `\x1B\\` (ST), as well as other C1 control characters.
