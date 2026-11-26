# OpenCTI case matches and transfer

OpenCTI is optional. Shellhound can check an IP or SHA-256 for links to other
incident cases. A separate reviewed transfer sends the saved case profile and
selected IPs, CVEs, file hashes and software.

## Configure

For case matching, save an HTTPS OpenCTI URL and a dedicated token with read
access to observables and incident cases. For transfers, also configure the
TAXII push ingester ID. Tokens remain in workspace settings and never enter case
archives or API responses. Changing the URL clears the previous token. TLS
verification and redirect refusal remain enabled.

Use **Test saved connection** explicitly to check the saved configuration and
TAXII write access. Active internal enrichment connectors must be manual: transfer
refuses configurations that could automatically start external enrichment.

## Check for earlier cases

- In **Settings → OpenCTI**, enable automatic checks for the displayed server
  and save. Previously configured connections start with this option off.
  Activation checks outstanding values in the current case. Other cases catch
  up when opened or when new findings arrive. Generated training cases stay local.
- As findings are saved, Shellhound checks each distinct client IP, IP recorded
  in a finding's log observation, and verified file SHA-256 once per case and
  connection. A file becomes eligible when its scan records the hash. Checks
  reuse stored evidence and run independently of the local analysis.
- Open the finding or its corresponding IOC to see the saved result and check
  time. Hits and misses are both remembered. Use **Recheck** for that value,
  or **Settings → OpenCTI → Recheck all** to refresh the current case's eligible
  findings. With automatic checks off, **Check OpenCTI** remains available
  for an explicit individual lookup.
- Open a case link to review the earlier incident. The result distinguishes an
  exact observable with visible linked cases, a known observable with no visible
  case links, and no visible match. The token's permissions determine visibility.
  Shellhound shows up to ten linked cases per value and marks a limited result.
  A match leaves all analyst decisions unchanged.

An unavailable OpenCTI server affects only the optional check. The local scan
keeps its own completion status. Match requests send the IP or SHA-256, with no
case profile, evidence contents or export. Checked results are saved in the case
database and travel with a case archive.

### Verify on your instance

1. Pick an IP or SHA-256 already linked **directly** to an incident case your
   token can read. Enable automatic checks in a different Shellhound case with
   a finding for that value. Open the finding and follow the returned case link.
2. Try an observable with no case links, then a value absent from your instance.
   Check that the two results are distinct. An unavailable server or denied
   request should show an error.
3. Reopen the finding and repeat the analysis. An unchanged value should keep
   its previous check time. Use **Recheck**, then **Recheck all**, and verify the
   times update. Turn automatic checks off and confirm a new finding stays local.

The query uses the observable's `containers` field to find incident cases that
directly contain it. It was checked against the
[OpenCTI 7.261103.0 schema](https://github.com/OpenCTI-Platform/opencti/blob/7.261103.0/opencti-platform/opencti-front/src/schema/relay.schema.graphql).

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
**Initial CVE** field accepts a CVE or a free-text description of the initial
vulnerability, such as `CVE-2026-12345` or `wp2shell` (one line, up to 200 characters).
Standalone CVE IDs are normalized to uppercase; free-text spelling is preserved.
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

Cases receive short readable labels in the reserved `SH ` namespace and the
fixed label `Webserver Compromise`. Examples: `SH Größe: 10–49`,
`SH Hosting: Cloud`, `SH Abfluss: bestätigt`, `SH Initial-CVE: CVE-2026-12345`.
Missing values use `unbekannt`. Providers and affected areas allow multiple
labels. The JSON Note preserves the full original field values.

The compact dashboard uses only these short labels, including its case cohort
and status filters. Legacy `shellhound:profile:` labels are no longer emitted.
On transfer, replacement labels are added and verified before stale SH or legacy
profile associations are detached. Unrelated labels remain unchanged, and global
Label objects are never deleted. Existing cases need a fresh reviewed transfer
or manual migration using [the label mapping](opencti-dashboard/LABELS.md).
The fixed workflow label does not prove technical compromise. Labels belong to
cases, never their shared organizations, CVEs, IPs or files.

## Review and transfer

1. Choose **Transfer to OpenCTI** from the IOC box, an object, or the case close flow.
2. Review the sanitized profile summary and the selected IPs, CVEs, hashes and software. Local
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

After verification, the receipt shows the number of distinct IP, CVE, hash and software
objects and links to the imported case on its original OpenCTI server. Pending or
failed work never displays a successful-transfer message or case link.

Hash-only File objects contain supported hashes, not filenames or source bytes.
Paths, domains, URLs, emails, usernames, evidence excerpts, notes and file samples
are never exported as IOCs. The profile transfers manually entered organization,
sector, location, dates, summary and marking. Older software/CVE profile details
are migrated to the IOC Box and only leave the case when selected there.
Software exports as a native STIX Software observable with its name, version and
vendor when available, linked to the Incident and included in the Case. CMS
installations collected in the IOC Box can be selected; plugins and themes need
to be collected there first. Inventory presence does not imply maliciousness.
Category, local installation paths and evidence contents are not transferred.
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

## Importable dashboard

A native dashboard for OpenCTI **7.261103.0**, its prerequisite STIX label
catalogue and German import instructions are in
[opencti-dashboard/README.md](opencti-dashboard/README.md). Import the catalogue
before the dashboard so portable label IDs resolve to local IDs. The dashboard
counts labelled cases; it does not calculate portfolio risk or loss costs.

## Offline checks

Run `python -m tools.opencti_smoke --offline` for an isolated, harmless export fixture.
The check never contacts OpenCTI or uploads data. Focused regression tests are
`tests.test_opencti_graph`, `tests.test_opencti_service`, `tests.test_opencti_client`,
`tests.test_opencti_api`, `tests.test_case_profile`, and `tests.test_profile_options`.
`tests.test_case_context` covers the additional profile fields, archive roundtrips
and their reviewed STIX context.

## Readable chart labels

Cases additionally receive `Webserver Compromise` and readable labels in the
reserved `SH ` namespace (for example `SH Größe: 10–49`). Legacy technical labels are no longer emitted and their case associations are removed after replacement verification. Synchronization verifies both managed namespaces and
the fixed case label, replacing stale associations while preserving unrelated
labels. These labels belong only to the Case-Incident, never shared entities.
The fixed label describes the Shellhound workflow; it does not establish compromise.
See [the complete label mapping](opencti-dashboard/LABELS.md) for manual updates
and [the dashboard import instructions](opencti-dashboard/README.md).
