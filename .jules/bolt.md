## 2025-05-22 - [IP Expansion Memory Optimization]
**Learning:** Returning a full list of IPs from CIDR expansion (e.g., for /16 or /8 ranges) can cause memory exhaustion (OOM) and significant performance delays due to large allocations.
**Action:** Always use generators/iterators for expanding large network ranges, and calculate the count of IPs mathematically instead of expanding the entire range.

## 2026-04-14 - [Concurrency Model: Batching vs Worker Pool]
**Learning:** Batch-based concurrency using `asyncio.as_completed` within sequential batches causes "head-of-line blocking." A single slow target in a batch prevents the next batch from starting, even if workers are idle.
**Action:** Use a worker-pool model with an `asyncio.Queue` for I/O-bound tasks with heterogeneous latency to ensure continuous processing and maximum worker utilization.

## 2026-05-15 - [Parallel Endpoint Probing Optimization]
**Learning:** Sequential probing of multiple service endpoints (e.g., Ollama, LM Studio, TextGen) during a scan causes significant cumulative delays, especially on non-target open ports where each probe must wait for a timeout.
**Action:** Use `asyncio.gather` to parallelize service detection probes at the same target, reducing the worst-case detection time to a single timeout duration.

## 2026-04-17 - [URL Formatting & Concurrent Detection]
**Learning:** Instantiating `ipaddress.IPv6Address` for every IP in a large scan is a significant bottleneck; a simple string ":" check is ~25x faster. Using `asyncio.wait` with `FIRST_COMPLETED` for multi-endpoint probing allows returning as soon as a server is identified, drastically reducing detection latency for positive targets.
**Action:** Use simple string heuristics for hot-path IP formatting and leverage early-exit concurrency patterns for multi-probe discovery tasks.

## 2026-04-20 - [Regex Optimization: Early Truncation]
**Learning:** Processing very large strings with regex substitutions (like ANSI escape or control character removal) can be an (n)$ bottleneck or even a DoS vector (ReDoS). If the final output is intended to be truncated to a fixed `max_len`, performing an early "safe" truncation (e.g., `2 * max_len`) before regex processing provides massive speedups (~400x+ for 1MB strings) and improves stability.
**Action:** Always consider early truncation for sanitization functions that have a defined maximum output length to bound the computational cost of text processing.

## 2026-05-20 - [Redundant Concurrency Control Bottleneck]
**Learning:** Layering multiple concurrency control mechanisms (e.g., a worker pool AND a semaphore of the same size) can accidentally throttle parallel sub-tasks (like parallel endpoint probes) that are launched within each worker, as they all compete for the same limited semaphore slots.
**Action:** Trust the worker pool and the underlying `aiohttp.TCPConnector` limits for request throttling, and avoid redundant semaphores that can bottleneck parallelization of sub-probes.

## 2026-05-25 - [Parallel Deep Scan & Pool Optimization]
**Learning:** Sequential metadata retrieval (e.g., fetching multiple model configs or process lists) for discovered hosts significantly increases per-target latency, especially when deep-scanning multiple models. Also, connection pool limits that don't account for sub-probes per worker can lead to starvation.
**Action:** Use `asyncio.gather` for concurrent metadata retrieval and scale `TCPConnector` limits to at least 4x the concurrency level to accommodate discovery probes and deep-scan requests simultaneously.
## 2026-05-25 - [Deep Scan Metadata Parallelization]
**Learning:** Sequential I/O-bound requests for host metadata (e.g., process lists and model configurations) create significant cumulative latency during deep scans. Even with a small number of requests (e.g., 4), parallelizing them with `asyncio.gather` can reduce total scan duration by ~60% in high-latency environments.
**Action:** Identify clusters of I/O-bound requests to the same host and use `asyncio.gather` to execute them concurrently instead of sequentially.

## 2026-05-28 - [Regex Optimization: Fast-path Substring Checks]
**Learning:** Using simple substring checks (`if 'char' in text`) or `regex.search()` before calling `regex.sub()` provides a measurable speedup (~1.7x) for text sanitization when the majority of strings are already "clean." This avoids the overhead of the regex engine's substitution logic entirely for clean paths.
**Action:** Always implement fast-path checks before regex substitutions in high-frequency text processing loops to optimize for the common "clean" case.

## 2026-06-02 - [IP Stringification Performance]
**Learning:** The `str()` method of `ipaddress.IPv4Address` and `ipaddress.IPv6Address` is significantly slower than using the standard library's `socket` and `struct` modules due to the overhead of Python's object model and validation logic. For high-throughput IP generation (e.g., scanning large networks), this becomes a major bottleneck.
**Action:** Use `socket.inet_ntoa(struct.pack('!I', int(ip)))` for IPv4 and `socket.inet_ntop(socket.AF_INET6, int(ip).to_bytes(16, 'big'))` for IPv6 stringification in hot paths to achieve 3x-11x faster IP expansion.

## 2026-06-05 - [IP Expansion Iteration Optimization]
**Learning:** Even when using fast `socket` stringification, iterating directly over `ipaddress.IPv4Network` or `ipaddress.IPv6Network` objects still causes the instantiation of a new `IPv4Address`/`IPv6Address` object for every IP in the range. For large CIDR blocks, this object creation overhead is a significant bottleneck.
**Action:** Iterate over CIDR ranges using `range(int(network.network_address), int(network.broadcast_address) + 1)` and perform integer-to-string conversion directly from the loop variable. This avoids all per-IP object instantiation and provides an additional ~2x speedup on top of stringification optimizations.

## 2026-06-10 - [Regex Optimization: Fast-path isprintable()]
**Learning:** Using `str.isprintable()` as a first-pass check in text sanitization provides a significant speedup (~1.7x) for clean strings by bypassing the regex engine entirely. Since `isprintable()` is implemented in C and covers most control characters and ANSI escapes (which are non-printable), it serves as an efficient filter for the common "already clean" case.
**Action:** Use `str.isprintable()` as a fast-path guard before performing complex regex-based sanitization on strings from untrusted sources.
