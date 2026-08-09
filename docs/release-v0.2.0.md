# SHELLHOUND 0.2.0

This release turns the first workbench into a broader, inspectable DFIR tool:
more evidence formats, analyst-owned rules, explicit limits on conclusions and
a test strategy built from the shapes that exposed real defects.

## Highlights

- **YARA and SIGMA rule management.** File and access-log rules can be added,
  validated and switched off from the workspace without changing shipped
  rules.
- **More evidence.** Error logs, log-coverage gaps, generic CMS installations
  and CMS extensions now participate in the investigation.
- **Honest time handling.** Every rendered time names its zone, the log and UTC
  readings can be switched, and clock offsets remain visible in the case
  chronology.
- **Reproducible hunt patterns.** Shipped and analyst-owned patterns remain
  separate, carry their limitations and record unsuccessful hunts too.
- **English and German interface.** The language changes at runtime while
  stored case data remains stable.
- **Safer exports.** Case archives cannot escape the workspace, host paths do
  not leak into exports and unknown response sizes remain unknown instead of
  becoming zero.

The full list of changes and the reasoning behind each detection change are in
[`CHANGELOG.md`](../CHANGELOG.md).

## Package installation

Release wheels contain the complete interface. Node.js is required only on the
machine that creates a release artifact:

```bash
pip install build
python -m build
pip install dist/shellhound-0.2.0-py3-none-any.whl
shellhound
```

CI installs the wheel outside the checkout and checks the rendered start page,
one hashed frontend asset and the authenticated `/api/state` endpoint. This is
deliberately an installation test, not merely an inspection of the zip file.

## Upgrading from 0.1.x

```bash
git pull
pip install -r requirements.txt
cd web && npm ci && npm run build && cd ..
python -m server.main
```

Existing cases are upgraded when opened. Derived log indexes whose schema is
older are rebuilt from the registered evidence; the original evidence is not
modified.

## Release verification

- Backend suite on Linux and Windows, Python 3.10 and 3.14.
- Frontend tests, type checking, lint and production build.
- Wheel installation and live HTTP smoke test from outside the repository.
- Nightly mutation runs remain advisory and publish their surviving mutants.

If the installed start page or an authenticated state request fails, do not
publish the artifact. Reinstall `0.1.1` and retain the workspace unchanged;
derived indexes can be rebuilt after the cause is corrected.

## Licence

[Apache-2.0](../LICENSE). Third-party components: [NOTICE](../NOTICE).
