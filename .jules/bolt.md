## 2026-04-03 - [IP Range Expansion OOM Prevention]
**Learning:** Expanding large CIDR ranges (like /16 or /8) into a list of IP strings in Python can quickly consume gigabytes of RAM. For example, a /16 range results in 65,536 IPs, while a /8 range results in over 16 million.
**Action:** Use Python generators and `yield` for IP expansion. Implement mathematical counting for range sizes instead of `len(list)` to avoid unnecessary memory allocation when calculating progress or total target counts.
