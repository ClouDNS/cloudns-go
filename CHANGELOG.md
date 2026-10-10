## 1.1.0 (2026-10-10)

- Add zone DNSSEC availability checks, signing activation/deactivation, NSEC3 opt-out control, and DS/DNSKEY retrieval.
- Add context support and request/response tests for DNSSEC operations.
- Remove an obsolete repository URL from the zone-update error message (#6).
- Repair failover request tests for the current API types (#7).

The additions preserve existing API compatibility.
