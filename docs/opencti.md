# OpenCTI transfer

OpenCTI integration transfers the manually saved case profile and selected
IPs, CVEs and file hashes. There is no OpenCTI lookup, score display, label import,
connector enrichment, Indicator creation or original-file upload.

## Configure

In Settings, save an HTTPS OpenCTI URL, a dedicated integration token and the
TAXII push ingester ID. Tokens remain in workspace settings and never enter case
archives or API responses. Changing the URL clears the previous token. TLS
verification and redirect refusal remain enabled.

Use **Test saved connection** explicitly to check the saved configuration and
TAXII write access. Active internal enrichment connectors must be manual: transfer
refuses configurations that could automatically start external enrichment.

## Fill the case profile

Enter the organization name, summary, country codes, region, city and incident
dates manually. Countries use two-letter codes such as DE and AT. Organization
names are no longer generated or suggested from a registry.

Main sectors come from a fixed local catalogue: Public administration, Healthcare,
Financial services, Energy, Water and wastewater, Technology, Telecommunications,
Transport and logistics, Manufacturing, Retail, Food and agriculture, Education
and research, Media and culture, Professional services, Construction and real
estate, Hospitality and tourism, Non-profit organisations, and Other.

Enter any subsectors manually and associate each with a selected main sector.
Software and CVE context can be edited manually in the case profile. CVE context
retains the analyst's assessment; it does not attribute exploitation to every IP.
TLP:AMBER+STRICT remains the default marking.

Saving a profile is local and never starts a transfer. Existing profile values,
including older sector names, remain readable and are preserved on partial edits.

## Review and transfer

1. Choose **Transfer to OpenCTI** from the IOC box, an object, or the case close flow.
2. Review the saved profile and the selected IPs, CVEs and hashes. Unsupported IOC
   types cannot be selected through the API either. IP tags become object labels.
3. Confirm the reviewed preview. A profile can also be transferred without IOCs.
4. Check the transfer receipt. Queue acceptance is distinct from verified import.
   Retry incomplete work from the receipt instead of starting duplicate imports.

Hash-only File objects contain supported hashes, not filenames or source bytes.
Paths, domains, URLs, emails, usernames, evidence excerpts, notes and file samples
are never exported as IOCs. The profile can contain manually entered organization,
sector, location, software and CVE context. Local paths and credentials are redacted
from transferred text. An IOC's case association does not assert maliciousness.

The server binds a preview to the case contents and destination. Changed data,
credentials or mappings require a new preview. Existing shared objects are reused
without overwriting another author's fields or markings. Completion requires
consistent TAXII status and visible imported objects. Reviewed IP tags are added
and verified even on reused IPs; existing remote tags are retained. The integration
account needs permission to create labels and attach them to these IPs. Receipts survive failures,
and completed batches are not resubmitted during retry.

Older receipts for removed functionality remain local history and cannot be
replayed. Create a fresh preview under the reduced transfer model. No existing
remote OpenCTI data is deleted by this change.

Direct VirusTotal and AbuseIPDB report lookups remain separate, explicit actions
and work independently of the OpenCTI export connection.

## Offline checks

Run `python -m tools.opencti_smoke --offline` for an isolated, harmless export fixture.
The check never contacts OpenCTI or uploads data. Focused regression tests are
`tests.test_opencti_graph`, `tests.test_opencti_service`, `tests.test_opencti_client`,
`tests.test_opencti_api`, `tests.test_case_profile`, and `tests.test_profile_options`.
