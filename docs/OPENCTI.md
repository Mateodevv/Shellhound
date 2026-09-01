# OpenCTI integration

Shellhound's OpenCTI integration is an analyst-driven exchange, not a sync.
Nothing is looked up or published in the background. OpenCTI context stays a
timestamped external snapshot and cannot change a finding, severity, file
decision, or actor triage state.

The implementation targets OpenCTI 7.x and uses two supported interfaces:

- TAXII 2.1 pushes the selected STIX bundle into a dedicated TAXII Push
  ingester.
- GraphQL performs exact lookups, reads direct relationships and uploads the
  content of selected evidence files to the imported Artifact observable.

No connector process and no `pycti` installation are required. OpenCTI's
[TAXII Push documentation](https://docs.opencti.io/latest/usage/import/taxii-push/)
describes the server-side ingester; its
[data model documentation](https://docs.opencti.io/latest/usage/data-model/)
explains the STIX 2.1 entity and relationship model used here.

## OpenCTI administration

Use a dedicated service user. Do not use an administrator or a token with
"bypass all capabilities". Its role needs:

- access to the knowledge and markings that Shellhound may look up;
- `KNOWLEDGE_KNUPDATE` (create/update knowledge);
- `KNOWLEDGE_KNUPLOAD` (upload knowledge files).

Shellhound checks both capability names when testing the connection. Normal
OpenCTI marking and confidence restrictions still apply to every API request.

Then prepare the OpenCTI side:

1. Create or select an Organization identity that represents the source of
   Shellhound reports.
2. Create the permitted marking definitions, for example TLP:AMBER.
3. Create a dedicated TAXII Push ingester and collection for Shellhound.
4. Give the service user access to that collection, organization and marking.
5. Copy the OpenCTI base URL, user API token, and complete TAXII collection
   object URL. All URLs must use HTTPS and must not contain credentials.

Keep the instance on a currently supported OpenCTI 7.x security release. The
integration deliberately does not set authorization-bypass headers or disable
TLS certificate validation.

## Shellhound configuration

Open **Settings → Intelligence**, enter the three connection fields, and save:

- OpenCTI base URL, including a configured base path if one exists;
- API token;
- TAXII 2.1 collection object URL.

Select **Test connection**. A successful check records only the OpenCTI
version, service user name, capability names, organizations and markings. The
token is stored in `<workspace>/settings.json`, is returned to the UI only as
its last four characters and is never copied into a case archive.

After the test, select the source Organization and default marking. OpenCTI
actions do not appear in cases until connection, author and marking are all
configured. Changing URL, token or TAXII collection invalidates the test and
hides the case actions again.

## Investigation workflow

**Fall mit OpenCTI abgleichen / Check case with OpenCTI** explicitly checks
the supported IOCs, actor IPs and confirmed file hashes. Every result stores
its fetch time. Refresh is always manual. Only exact normalized observable
matches are accepted; OpenCTI search ranking alone is not treated as a match.

IOC rows, actor details and file details show the stored match, score, labels,
markings, Indicators and first-degree relationships to Malware, Threat Actors,
Campaigns and Reports. An actor IP always remains an IP observable. A related
observable can enter the IOC box only after the analyst clicks the promotion
action; its OpenCTI object ID and snapshot provenance are then retained.

Use **Für OpenCTI vormerken / Add to OpenCTI package** on an IOC, actor, file,
or confirmed finding. The package builder persists only this draft selection.
Before publishing it shows:

- every STIX object and relationship;
- the editable release assessment;
- author and marking;
- whether an observable is also explicitly emitted as an Indicator;
- for files, relative path, hashes, MIME type and size.

Selecting a file always uploads its binary content. Shellhound imposes no
additional size limit, so review the displayed size and the OpenCTI deployment
limit before confirming. Absolute evidence paths are never included.

Every confirmation creates a new immutable STIX Report snapshot. Observable
IDs are deterministic, allowing several reports or cases to refer to the same
value; Report and Note IDs belong to that publication. An identical package
requires a second confirmation.

## Failure handling

The state sequence is `previewed → publishing → published`, with `partial` or
`failed` as explicit outcomes. Shellhound pushes the TAXII objects first and
then uploads selected files. It does not retry automatically and does not
delete successfully imported remote objects after a later failure.

For a partial publication, **Retry** attempts only file rows that are not yet
uploaded. A failed TAXII push repeats the stored immutable bundle. Before,
during and after every file upload Shellhound re-checks file identity, size and
SHA-256; changed or escaped evidence is refused. Errors stored in the case
contain a code and sanitized summary, never a token, response body, absolute
path or file content.

## Data boundaries

Lookups send one normalized observable value at a time. Publishing sends only
the visible previewed STIX objects and, for every selected file, its content.
GraphQL uses fixed documents and variables, redirects are not followed, TLS
verification remains enabled, and remote strings are rendered as data.

Shellhound's existing CSV, JSON and STIX exports are unchanged by this
integration.
