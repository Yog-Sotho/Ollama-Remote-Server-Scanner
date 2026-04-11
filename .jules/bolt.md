## 2025-05-22 - [IP Expansion Memory Optimization]
**Learning:** Returning a full list of IPs from CIDR expansion (e.g., for /16 or /8 ranges) can cause memory exhaustion (OOM) and significant performance delays due to large allocations.
**Action:** Always use generators/iterators for expanding large network ranges, and calculate the count of IPs mathematically instead of expanding the entire range.

## 2026-04-11 - [Sliding Window Concurrency vs. Batching]
**Learning:** Batch-based processing in network scanners causes "head-of-line blocking," where the entire batch waits for the slowest host. A sliding window model keeps the concurrency pipe full and significantly improves performance on sparse or high-latency networks.
**Action:** Replace `for batch in _batch_iterator` patterns with a set of active tasks and `asyncio.wait(..., return_when=asyncio.FIRST_COMPLETED)` to maintain constant throughput.
