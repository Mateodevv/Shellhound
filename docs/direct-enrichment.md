# Direct reputation enrichment

When OpenCTI is not configured, **Settings > Direct enrichment** accepts VirusTotal
and AbuseIPDB keys. The same section is available in the workspace settings dialog.
Keys stay in the local workspace settings file, masked in API responses and excluded
from case archives. Saving or removing a key does not contact a provider.

Files and clients expose the existing **Enrichment** review tab; linked files from
log findings and supported objects in the IOC Box use the same provider reports.
As with OpenCTI, collect an artifact into the IOC Box first. Missing providers and
unsupported object types do not expose enrichment actions.

- VirusTotal retrieves existing reports for MD5, SHA-1 and SHA-256 hashes, IPv4/IPv6,
  domains and HTTP(S) URLs. Files are queried by hash; file bytes are never uploaded.
- AbuseIPDB checks IPv4/IPv6 with a 90-day reporting window. It does not submit reports.
- Lookup is explicit. Opening tabs or settings does not call either provider. Stored
  reports remain visible until an explicit Refresh; failures preserve the last result.
- Provider metrics retain their original meaning: malicious-engine counts are not an
  abuse-confidence score. Provider opinions never change local findings or triage.
- Configured OpenCTI takes precedence on both client and server. Connection errors do
  not cause automatic failover. Direct keys remain saved for later use if OpenCTI is
  removed from configuration.

Requests use GET, fixed HTTPS provider endpoints, bounded responses and timeouts.
Redirects are rejected to prevent forwarding keys. Authentication and rate-limit
errors are shown without provider response bodies or credentials. Successful and
failed requests are recorded in the local diagnostic log with a hashed target value.

API references: [VirusTotal file reports](https://docs.virustotal.com/reference/file-info),
[IP reports](https://docs.virustotal.com/reference/ip-info),
[domain reports](https://docs.virustotal.com/reference/domain-info),
[URL reports](https://docs.virustotal.com/reference/url-info),
[AbuseIPDB check](https://docs.abuseipdb.com/#check-endpoint).
