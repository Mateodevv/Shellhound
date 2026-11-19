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

Each main sector has a fixed local list of matching subsectors, selected directly
within its group. New free-text values and cross-sector choices are rejected by
the server. Existing custom values remain selectable as saved values; they are
not renamed or deleted when the profile is edited.
CVEs are managed in the IOC Box. The profile editor also has an optional
**Initial CVE** field for the CVE associated with initial access. Enter one
identifier such as `CVE-2026-12345`; lowercase input is normalized to uppercase.
Leave it empty if unknown. No value is inferred from the IOC Box or older CVE
lists, and entering a CVE does not confirm exploitation. Previously saved
software and CVE profile details remain stored locally,
including in archives; editing the simplified form does not erase them.
TLP:AMBER+STRICT remains the default marking.

Saving a profile is local and never starts a transfer. Existing profile values,
including older sector names, remain readable and are preserved on partial edits.

The profile also records company size by employee band, the affected system's
hosting model and providers, IT operating model, initial access route and its
assessment, confirmed affected areas, exfiltration and attacker-encryption status,
discovering party and discovery method. Use the company and system configuration
immediately before the incident. Choose hosting providers from the dropdown;
several providers can be added. Use **Other provider** for an unlisted name.
Previously saved custom names remain available and are not replaced by the catalogue.

Missing values remain unknown. Exfiltration and encryption distinguish unknown,
not investigated, no evidence found, suspected and confirmed. An empty affected-area
selection means unknown, not that the incident stayed on the web server. Saved
values are restored when editing, including after archive import. CMS detections,
IP-provider reports and the first known evidence event do not reliably establish
these facts, so they are not used to prefill incident conclusions or company details.

Export includes a generated STIX Note
linked to the Incident and contained in its Case. Its JSON content uses the schema
`shellhound.case-context/v1` and preserves the reviewed field names and values,
including uncertainty. This requires no custom OpenCTI schema; it is stored as
Note content, not as native dashboard-filterable custom fields. It never includes
local case or IOC notes. The preview shows the same context before confirmation.

### Community Edition: filterable case labels

The Incident Response case also receives a label for each profile value, using
the reserved namespace `shellhound:profile:<field>:<value>`. Scalar fields have
one label; providers and affected areas have one per value. Missing values use
an explicit `unknown` label. Values are lowercased, deduplicated and sorted;
the JSON Note preserves original provider spelling. No organization name,
summary, local notes or source paths become profile labels. These labels belong
only to the case, not its shared IPs, hashes, CVEs or organization.

Examples:

```text
shellhound:profile:employee_count:10-49
shellhound:profile:hosting_model:managed_hosting
shellhound:profile:hosting_providers:hetzner
shellhound:profile:initial_cve:cve-2026-12345
shellhound:profile:data_exfiltration:not_observed
shellhound:profile:spread:web_server
```

Use **Label** filters on Incident Response cases, including dashboard widgets.
The initial CVE is included in the context Note and case labels; clearing it
exports `shellhound:profile:initial_cve:unknown`. It does not automatically
create a vulnerability IOC or an exploitation relationship. To transfer a
Vulnerability object, select the corresponding CVE in the IOC Box as usual.
For example, combine `shellhound:profile:hosting_model:managed_hosting` AND
`shellhound:profile:data_exfiltration:confirmed` to count these cases. Labels
are categories, not numeric or date fields for arithmetic or range comparisons.

After TAXII imports the case, explicit GraphQL label updates add missing labels
and check their visibility before detaching old
labels in the reserved namespace. Labels outside `shellhound:profile:` are
retained, including other Shellhound labels. Global Label objects are never
deleted. The final reserved label set must exactly match the reviewed preview
before a receipt becomes complete. Permission failures or mismatches remain
incomplete; retry checks labels again without resubmitting completed TAXII batches.

## Review and transfer

1. Choose **Transfer to OpenCTI** from the IOC box, an object, or the case close flow.
2. Review the sanitized profile summary and the selected IPs, CVEs and hashes. Local
   paths and credentials are shown as redacted values; the saved profile stays unchanged. The
   close flow opens this same preview directly, without a separate profile step. Unsupported IOC
   types cannot be selected through the API either. IP tags become object labels.
3. Check the destination URL, TAXII collection and TLP beside the confirmation,
   then confirm the reviewed preview. A profile can also be transferred without IOCs.
4. Check the transfer receipt. Queue acceptance is distinct from verified import.
   Retry incomplete work from the receipt instead of starting duplicate imports.

An unchanged selection matching the latest successful transfer to this destination
is marked as already transferred and cannot be submitted again. The comparison uses
exported objects, so local-only notes and token rotation do not create changes.
Changed profile content, IOC selection, tags or marking can be transferred again.
An intervening incomplete transfer requires review instead of assuming an older
successful snapshot still describes the remote case. This is a local receipt check,
not a live comparison against later changes made directly in OpenCTI.

After verification, the receipt shows the number of distinct IP, CVE and hash
objects and links to the imported case on its original OpenCTI server. Pending or
failed work never displays a successful-transfer message or case link.

Hash-only File objects contain supported hashes, not filenames or source bytes.
Paths, domains, URLs, emails, usernames, evidence excerpts, notes and file samples
are never exported as IOCs. The profile transfers manually entered organization,
sector, location, dates, summary and marking. Older software/CVE profile details
are not exported separately: only CVEs selected from the IOC Box leave the case.
Local paths and credentials are redacted
from transferred text. An IOC's case association does not assert maliciousness.

The server binds a preview to the case contents and destination. Changed data,
credentials or mappings require a new preview. Existing shared objects are reused
without overwriting another author's fields or markings. Completion requires
consistent TAXII status and visible imported objects. Reviewed IP tags are added
and verified even on reused IPs; existing remote tags are retained. The integration
account needs permission to create labels, attach them to IPs and cases, and
remove outdated profile-label associations from cases. Receipts survive failures,
and completed batches are not resubmitted during retry.

Older receipts for removed functionality remain local history and cannot be
replayed. Create a fresh preview under the reduced transfer model. No existing
remote OpenCTI objects are deleted by this change.

Direct VirusTotal and AbuseIPDB report lookups remain separate, explicit actions
and work independently of the OpenCTI export connection.

## Offline checks

Run `python -m tools.opencti_smoke --offline` for an isolated, harmless export fixture.
The check never contacts OpenCTI or uploads data. Focused regression tests are
`tests.test_opencti_graph`, `tests.test_opencti_service`, `tests.test_opencti_client`,
`tests.test_opencti_api`, `tests.test_case_profile`, and `tests.test_profile_options`.
`tests.test_case_context` covers the additional profile fields, archive roundtrips
and their reviewed STIX context.
