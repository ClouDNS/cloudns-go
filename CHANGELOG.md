## 1.2.0 (2026-10-10)

- Stop printing Dynamic DNS URL responses and parsed credentials to stdout.
- Use the standard HTTP transport for API requests, enabling offline request interception.
- Add regression tests for Dynamic DNS URL reads and rotations without logging secrets.

## 1.1.0 (2026-10-10)

- Add zone DNSSEC availability checks, signing activation/deactivation, NSEC3 opt-out control, and DS/DNSKEY retrieval.
- Add context support and request/response tests for DNSSEC operations.
- Remove an obsolete repository URL from the zone-update error message (#6).
- Repair failover request tests for the current API types (#7).

The additions preserve existing API compatibility.
