## 2025-05-22 - [IP Expansion Memory Optimization]
**Learning:** Returning a full list of IPs from CIDR expansion (e.g., for /16 or /8 ranges) can cause memory exhaustion (OOM) and significant performance delays due to large allocations.
**Action:** Always use generators/iterators for expanding large network ranges, and calculate the count of IPs mathematically instead of expanding the entire range.

## 2026-04-05 - [Sliding Window Concurrency for Scanners]
**Learning:** Discrete batch-by-batch processing (using `asyncio.as_completed` on fixed chunks) causes "head-of-line blocking" where one slow task stalls the entire batch, leaving concurrent slots idle.
**Action:** Use a sliding window pattern with a `pending` set and `asyncio.wait(..., return_when=asyncio.FIRST_COMPLETED)` to refill the task queue as soon as any single task finishes, maintaining maximum throughput.
