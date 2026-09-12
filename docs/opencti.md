# OpenCTI integration

Shellhound keeps evidence, investigation and triage local. OpenCTI stores shared
intelligence and runs external enrichment connectors. Local GeoIP remains local.

## Structured IOC objects

The IOC box uses a paginated object list beside a persistent detail pane. Type tabs,
positive filters and search cover the whole case. Files are searchable by name and
hash. Overview, Evidence, Relationships and OpenCTI separate the investigation
steps; tooltips explain individual fields. Object links retain a back history and
filters. Opening a row is separate from checkbox selection, which starts empty.
Select page or Select all filtered explicitly to prepare a batch action. The action
count includes file hash entries. New arrivals never join an existing selection.
Opening details never starts enrichment or transfer. On narrow screens, Back
restores the object list. Activity contains transfer receipts and full/filtered
downloads; POST /api/cases/{slug}/iocs/export accepts ids and format for downloads.

Files have a content identity, coherent hashes and multiple recorded locations.
The file browser and confirmed findings collect these automatically. Existing hash
entries remain available inside the file card. Different content at the same path
is a different file; a matching filename is never sufficient to combine hashes.
Missing originals do not erase recorded file metadata. Samples still require an
explicit selection and a fresh matching hash before upload.
For migrated records, **Verify available file metadata** reads only registered
local evidence and adds secondary hashes/size when SHA-256 still matches. Changed
or missing locations are reported; verification does not upload content.

Path context distinguishes HTTP paths, investigated system paths and local evidence
paths. Local paths never appear in OpenCTI transfers. Account context identifies the
system in which a username is meaningful; unscoped usernames remain case Notes.
The context itself is not sent as an account identifier: a stable scoped digest is
used to prevent merging unrelated accounts.

Each object starts **malicious**, following the IOC-box default policy. Analysts can
change the assessment with a reason and retained history. Migration applies this
default to old unassessed objects without assessment history; manual assessments
remain intact. Indicator suggestions from assessments require an explicit manual
malicious assessment. This is independent of
finding triage, file classification and remote intelligence. Indicator selection
remains a separate export decision.

Relationships carry direction, automatic/manual provenance and supporting evidence.
Use **Add evidence-backed relationship** to attach a specific log/finding reference,
optionally an observation and a time range. A CVE can be added to the box by its
identifier. Request-path context, observed use, execution, exploitation attempts
and confirmed exploitation remain distinct assertions. An HTTP 2xx response alone
establishes neither execution nor exploitation. The adapter preserves unsupported
relationship semantics in a case-owned `related-to` with the reviewed evidence
in its description. It does not generate an additional Note for every edge.

Pattern Hunt tests (individual and batch) automatically add every matched IP and
link it to valid CVE identifiers explicitly entered in the pattern's CVE field.
This includes clients beyond the displayed result limit and the current draft's
CVE metadata. Each link retains the test, rule/index fingerprints, request count,
time range and an example log reference. A match creates CVE context, not a verdict
or proof of exploitation. Patterns without CVEs or without hits add no such links.
Retesting preserves explicit relationship withdrawals. Transfer remains a separate
reviewed action; tests never contact OpenCTI or enrichment services.

Withdrawal requires a reason and is visible in history. A repeated automatic
collection does not silently undo a withdrawn relationship. The next reviewed
transfer withdraws earlier owned statements while preserving shared objects and
other sources' assertions. Notes/evidence exclusions also apply to assessment
reasons and relationship evidence.

Schema 15 preserves existing IOC IDs, source UIDs, notes and export receipts.
Explicit historical SHA-256 provenance creates file records without inventing
size, secondary hashes or a classification. Unknown legacy contexts and equivalent
legacy values are retained with review warnings. Migration never initiates export.
Historical file-location and request-context relationships require matching source
artifacts. Ambiguous content versions retain their path context without an inferred
IP-to-file assertion. Later migrations preserve verified metadata and withdrawals.

Local detail/decision APIs: `GET /api/cases/{slug}/iocs/{id}/detail`,
`POST /api/cases/{slug}/iocs/{id}/assessments`,
`POST /api/cases/{slug}/ioc-relationships`, and
`POST /api/cases/{slug}/ioc-relationships/{id}/withdraw`.
IOC creation/update also accepts `context` and `path_context`; listing adds file
metadata, membership, summary and assessment. Invalid relationships return 400,
missing endpoints 404, and conflicting identity corrections 409.

## Configure the connection

1. Open **Settings → OpenCTI**. Enter the final HTTPS URL, an existing dedicated
   integration token and the TAXII push ingester UUID. Personal passwords do not
   belong in these settings. Reuse the existing Shellhound ingester.
2. In the OpenCTI deployment, set internal enrichment connectors to manual
   (`CONNECTOR_AUTO=false` where supported by that connector). Keep external
   feed import schedules enabled. Recreate/restart only the affected connector
   services using the deployment's normal workflow, then confirm their OpenCTI
   overview shows a manual trigger. The connection test lists active automatic
   enrichments; transfers remain blocked until these are changed.
3. The integration account needs read access to visible knowledge, TAXII push
   permission, **Access connectors** (`MODULES`) to inspect connector metadata,
   **Ask for knowledge enrichment** (`KNOWLEDGE_KNENRICHMENT`), and (only when enabled) artifact
   upload permission. Grant access to the selected TLP marking as well. A token
   with narrower visibility can legitimately return no visible result.
4. Use **Test connection**. This reads capabilities and connector metadata; it
   neither sends evidence nor triggers enrichment.

If the test reports that connection and TAXII write access succeeded but
connector metadata was denied, the token is valid. Check **Access connectors**
in the integration user's assigned role under **Settings → Security → Roles**.
Until the connector configuration can be inspected, transfer remains blocked;
the connector check must not be skipped.

The token lives in workspace `settings.json`, outside case archives. Responses
and previews never return it. Changing the URL clears the old token. TLS remains
verified and redirect responses are refused. Existing direct-provider keys are
ignored and removed on the next settings write.

## Prepare a case

Set a unique **Case ID**, for example `PIM-5165`. Empty IDs are allowed for local
work, but cannot be exported. The first queued transfer locks the ID to prevent
later updates becoming a different OpenCTI incident. Active and archived IDs
are reserved in the workspace.

Choose or generate a random organization pseudonym. The registry stores the
pseudonym and its UUID only; there is no customer-name field or reverse mapping.
Select the same pseudonym for later cases involving the same organization.

Optional profile fields include summary, sectors, ISO alpha-2 country codes,
incident dates, software versions and vulnerabilities. Vulnerabilities carry
`confirmed` or `suspected` exploitation status. CVEs are represented as
Vulnerability objects; non-CVE observations remain explicit context. The default
marking is **TLP:AMBER+STRICT**. This expresses intended sharing restrictions; it
does not replace OpenCTI's access controls.

## Use the IOC box

- **Check in OpenCTI** searches existing observable values. Contextual path,
  user and other entries remain visible but are not sent to external reputation
  providers. Results retain sources, dates, reports and relationships. No visible
  match means unknown to the integration account, not benign.
- **Transfer to OpenCTI** opens a preview of the complete selected graph,
  including collapsed rows. Review individual IOCs, relations, notes, evidence,
  profile fields and suggested Indicators. Indicators require explicit selection;
  extracted domains and HTTP requests do not become malware or C2 assertions.
- **Enrich via OpenCTI** shows matching active connectors. Unknown values require
  explicit permission to create marked observables before the selected connector
  runs. Requests never change Shellhound's triage state.

Every new transfer creates or updates an **Incident Response case**
(`x-opencti-case-incident`) containing the **Incident**, the affected organization,
sectors/subsectors, locations, software, CVEs and selected investigation results.
The Case represents the investigation; the Incident represents the security event.
No Report is generated by default. The OpenCTI workflow remains under OpenCTI's
control; archiving the local case does not silently close its remote counterpart.
Source UUIDs survive edits. File hashes
come from one verified snapshot; ambiguous evidence roots or changed file
versions are visible problems instead of guessed associations.

Each exported observable has a neutral description with the case ID and a pointer
to the investigation. Assessments, classification, provenance and evidence stay
in case-owned Notes and retain the preview's exclusions. File/hash entries that
resolve to the same content share one context Note. Paths retain separate
occurrence Notes; common profile Notes are consolidated into one case-context
Note. No context from an unselected IOC is included. Descriptions use one managed
section per case; repeat exports replace that section while preserving other
authors and other cases. A shared observable with a different marking requires
review before adding case context to its description. Description failures are
recorded as partial transfers and can be resumed without repeating imports or
sample uploads. Previously uploaded, hash-matched samples also receive context.

Every observable is directly associated with the Incident. An IP requesting a
path stays connected to that path's context. That request is not projected onto
the File, Malware or Artifact collected later. A separate, evidence-backed use
or execution relationship can express stronger knowledge.
A direct IP-to-CVE link requires a confirmed, active IP-scoped finding naming
that CVE; a CVE in the case profile alone is connected through the Incident.

File classifications (Webshell, Dropper, SEO-Spam and others) remain labels and
case context. A Malware entity additionally requires confirmed, verified content
and a selected Indicator or an evidence-backed use/execution relationship.
Webshell Indicators are preselected in the wizard and can be unchecked. Merely
having a classification tag never creates a Malware entity. Matching File/hash
entries reuse the same Malware entity. Generic malware remains an unknown type
without family attribution. Confirming ordinary or YARA findings exports the
File and its case context without inferring a malware classification. Changing or withdrawing an
explicit classification replaces or retracts the previous owned assertion.

An HTTP acceptance is not a successful import. Receipts preserve TAXII work IDs,
batch progress and per-sample upload results. **Resume** checks pending work and
continues unfinished steps. Changes to the case, file identity, destination or
reviewed content require a new preview. Deleting local rows does not delete
shared OpenCTI objects. A later preview identifies withdrawn owned assertions;
reactivated assertions receive a new generation when STIX revocation is terminal.

Older Report-based export receipts can still be resumed. New exports use the Case
container and leave old Reports as history. Consolidated Notes replace earlier
owned context Notes; they do not erase the previous assessments. Old, owned
Report-scoped Artifact context edges are retired before the Case-scoped edges are
added, avoiding duplicate active relationships. Third-party edges are untouched.

## Original samples and privacy

Samples are off by default. Enable optional uploads in Settings, then select each
original in the preview. The upload limit is 25 MiB per file. The worker verifies
the exact selected bytes and SHA-256, uploads an Artifact through GraphQL, and
links it to the File (`obs_content` and `related-to`) and Case container. Only
reviewed content-specific Notes, confirmed Malware and the Incident are inherited
by the Artifact; path requests, IP addresses and CVEs are not copied. An upload failure does not erase a completed
metadata transfer. Archive extraction and script execution are not performed by
Shellhound.

Shellhound refuses manual enrichment of Artifacts and files with attached
content. This prevents forwarding original content when a connector's remote
upload settings cannot be verified. For metadata-only hash enrichment, use an
observable without an attached sample. Keep connector-side file forwarding
disabled as part of deployment configuration.

Preview domains, email addresses, paths, notes and evidence carefully. Random
pseudonyms do not anonymize this content. Local workstation paths and obvious
credentials are excluded/redacted, but free text can still disclose investigation
context. Nothing is sent merely by opening an IOC or reading cached results.

## Local acceptance

Run the OpenCTI client, graph, service, profile and HTTP tests plus the frontend
suite. Use an isolated synthetic case and a configured OpenCTI integration
account for deployment acceptance. Verify repeat exports, revoked/re-confirmed
assertions, partial retries, manually requested enrichment, markings and sample
links. Do not use real evidence for initial integration tests.

The acceptance helper creates a separate fixture with ten object types, seven
relationships and inert sample bytes. It reads the saved integration settings;
tokens are never command-line arguments. From the repository's Python environment:

```text
python -m tools.opencti_smoke --offline
python -m tools.opencti_smoke --workspace <configured-workspace>
python -m tools.opencti_smoke --workspace <configured-workspace> --transfer
```

The first command stays offline; the second only tests the connection and reads
existing knowledge. `--transfer` explicitly imports the synthetic case. Add
`--sample` to explicitly include the inert sample when sample uploads are enabled.
Fixtures, previews and proof files remain under `.shellhound/opencti-smoke`.
Pending work can be continued with `--resume <fixture-directory> --transfer`.
The helper does not request external enrichment or remove remote objects.

Relevant upstream references:

- [OpenCTI API](https://docs.opencti.io/latest/reference/api/)
- [TAXII push](https://docs.opencti.io/latest/usage/import/taxii-push/)
- [Enrichment](https://docs.opencti.io/latest/usage/enrichment/)
- [FIRST TLP](https://www.first.org/tlp/)

The dashboard and Pattern Hunt use the current main workflow, including saved
pattern checks. Explicit CVE metadata still links every matching IP during a
query preview or saved check, including results beyond the UI page limit.
CVE collection validates the same log index generation as the saved check.
IOC evidence links open the exact historical query without replacing an editor
draft. The integration schema also retains main's scan retries and skip reviews.
