## 2025-05-22 - [IP Expansion Memory Optimization]
**Learning:** Returning a full list of IPs from CIDR expansion (e.g., for /16 or /8 ranges) can cause memory exhaustion (OOM) and significant performance delays due to large allocations.
**Action:** Always use generators/iterators for expanding large network ranges, and calculate the count of IPs mathematically instead of expanding the entire range.

## 2026-04-12 - [Sliding Window Concurrency vs. Batch Processing]
**Learning:** Batch-based asynchronous processing (using `asyncio.as_completed` on discrete batches) causes head-of-line blocking where a single slow task stalls the entire batch.
**Action:** Use an `asyncio.Queue` worker-pool or a sliding window model with `asyncio.wait(..., return_when=FIRST_COMPLETED)` to maintain constant concurrency and maximize throughput in network-bound tasks.
