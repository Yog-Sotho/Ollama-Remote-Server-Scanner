## 2025-05-22 - [IP Expansion Memory Optimization]
**Learning:** Returning a full list of IPs from CIDR expansion (e.g., for /16 or /8 ranges) can cause memory exhaustion (OOM) and significant performance delays due to large allocations.
**Action:** Always use generators/iterators for expanding large network ranges, and calculate the count of IPs mathematically instead of expanding the entire range.

## 2026-01-15 - [Worker Queue Concurrency vs Batching]
**Learning:** In asynchronous network scanners, batch-based concurrency () suffers from "head-of-line blocking" where a few slow targets can stall the entire batch.
**Action:** Use a worker-pool model with  to maintain continuous throughput, allowing workers to immediately move to the next task as soon as they complete one.

## 2026-01-15 - [Worker Queue Concurrency vs Batching]
**Learning:** In asynchronous network scanners, batch-based concurrency suffers from 'head-of-line blocking' where a few slow targets can stall the entire batch.
**Action:** Use a worker-pool model with asyncio.Queue to maintain continuous throughput, allowing workers to immediately move to the next task as soon as they complete one.
