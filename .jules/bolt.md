## 2025-05-22 - [IP Expansion Memory Optimization]
**Learning:** Returning a full list of IPs from CIDR expansion (e.g., for /16 or /8 ranges) can cause memory exhaustion (OOM) and significant performance delays due to large allocations.
**Action:** Always use generators/iterators for expanding large network ranges, and calculate the count of IPs mathematically instead of expanding the entire range.

## 2026-04-06 - [Sliding Window Concurrency & O(1) Range Counting]
**Learning:** Discrete batching (processing N tasks, waiting for all to finish, then starting next N) causes head-of-line blocking where one slow timeout stalls the entire pipeline. Additionally, expanding full lists for IP counting causes OOM and O(N) delays.
**Action:** Use a sliding window concurrency model with `asyncio.wait(..., return_when=FIRST_COMPLETED)` to keep the task pool constantly saturated. Use mathematical O(1) calculations for counting range sizes instead of expanding them.
