## 2025-05-22 - [IP Expansion Memory Optimization]
**Learning:** Returning a full list of IPs from CIDR expansion (e.g., for /16 or /8 ranges) can cause memory exhaustion (OOM) and significant performance delays due to large allocations.
**Action:** Always use generators/iterators for expanding large network ranges, and calculate the count of IPs mathematically instead of expanding the entire range.

## 2026-04-14 - [Concurrency Model: Batching vs Worker Pool]
**Learning:** Batch-based concurrency using `asyncio.as_completed` within sequential batches causes "head-of-line blocking." A single slow target in a batch prevents the next batch from starting, even if workers are idle.
**Action:** Use a worker-pool model with an `asyncio.Queue` for I/O-bound tasks with heterogeneous latency to ensure continuous processing and maximum worker utilization.
