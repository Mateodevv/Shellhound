"""Isolated, repeatable OpenCTI acceptance using saved workspace settings.

Local fixture only: python -m tools.opencti_smoke --offline
Read-only remote checks: python -m tools.opencti_smoke --workspace <workspace>
Synthetic import: add --transfer (and --sample for the inert original file).
Resume pending work: add --transfer --resume <fixture-directory>.

No credential arguments, external enrichment, or remote deletion. Fixtures and
sanitized proof remain under .shellhound/opencti-smoke for inspection/recovery.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from server import db, ioc_model, opencti_graph as graph, opencti_service as service, workspace
from server.config import Config
from server.jobs import manager
from server.opencti_client import OpenCTIClient

_MARKER = "opencti-smoke.json"


def _write(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def _emit(value):
    print(json.dumps(value, ensure_ascii=False), flush=True)


def _fixture(output_root):
    suffix = uuid.uuid4().hex[:12]
    reference = "PIM-QA-" + datetime.now(timezone.utc).strftime("%Y%m%d") + "-" + suffix.upper()
    run_dir = Path(output_root) / suffix
    case = workspace.create_case(run_dir / "cases", "Synthetic OpenCTI acceptance", reference,
        notes="Synthetic test data only. No customer data or real malware.",
        profile={"summary": "Isolated Shellhound integration acceptance fixture; all data is synthetic.",
                 "countries": ["DE"], "sectors": ["Technology"],
                 "software": [{"name": "Shellhound QA fixture", "version": "0"}],
                 "vulnerabilities": [{"name": "Synthetic fixture weakness", "status": "suspected",
                                      "description": "No real vulnerability is asserted."}]})
    evidence = run_dir / "synthetic-evidence"
    evidence.mkdir()
    file = evidence / "inert-sample.txt"
    data = (f"Shellhound OpenCTI QA {reference}\nInert test bytes, not malware.\n").encode()
    file.write_bytes(data)
    domain = f"shellhound-{suffix}.example.test"
    values = {"ip": "198.51.100.42", "domain": domain, "url": f"https://{domain}/qa",
              "email": f"qa@{domain}", "path": "inert-sample.txt", "user": f"qa-{suffix}",
              "hash": hashlib.sha256(data).hexdigest(), "other": f"qa_table_{suffix}"}
    conn = db.connect(case)
    try:
        conn.execute("INSERT INTO evidence(kind,path,added) VALUES('webroot',?,?)", (str(evidence), db.now()))
        ids = {kind: db.add_ioc(conn, value, kind, note="Synthetic acceptance fixture") for kind, value in values.items()}
        for source, target, kind in (("hash", "path", "hash-of"), ("ip", "path", "requested"),
                                     ("domain", "other", "host-in"), ("email", "user", "account-of")):
            db.link_iocs(conn, ids[source], ids[target], kind, "Synthetic relationship only")
        # Exercise classification mapping with an explicitly synthetic source
        # finding. No attack code is generated, executed, or uploaded.
        db.upsert_finding(conn, "webshell", 0, "Synthetic webshell classification fixture", "file", str(file),
                          evidence="Synthetic test classification; the actual sample is inert text.", rule_id="qa.synthetic")
        conn.execute("UPDATE findings SET triage='confirmed'")
        for kind, role in (("hash", "hash"), ("path", "direct")):
            conn.execute("INSERT INTO ioc_sources(ioc_id,artifact,role,active,added) VALUES(?,?,?,1,?)",
                         (ids[kind], str(file), role, db.now()))
        file_id = ioc_model.collect_file(conn, str(file), values["hash"], ids["hash"], ids["path"], "webshell")
        ioc_model.assess(conn, file_id, "benign", "Synthetic inert acceptance bytes; the classification above tests mapping only.")
        ioc_model.relationship(conn, ids["ip"], file_id, "request-context", "Synthetic request record 1",
                               "Synthetic mapping test; neither execution nor exploitation is asserted.")
        # A real CVE identifier is used solely to test relationship compatibility.
        # This explicitly synthetic case asserts no activity against a real system.
        cve_id = db.add_ioc(conn, "CVE-2021-44228", "vulnerability", note="Synthetic mapping test only")
        ioc_model.relationship(conn, ids["ip"], cve_id, "cve-context", "Synthetic fixture record 2",
                               "Compatibility test, not evidence of exploitation.")
        conn.execute("UPDATE iocs SET context=?,identity_key=? WHERE id=?", (
            "synthetic-system-" + suffix, ioc_model.identity(values["user"], "user", "synthetic-system-" + suffix), ids["user"]))
        conn.commit()
    finally:
        conn.close()
    _write(case / _MARKER, {"schema": 1, "reference": reference, "hash_id": ids["hash"]})
    return case


def _wait(case, job_id, seconds, emit):
    deadline = time.monotonic() + seconds
    while manager.wait_for(case, [job_id], timeout=5):
        emit({"stage": "waiting", "job_id": job_id})
        if time.monotonic() >= deadline:
            manager.cancel(case, job_id)
            manager.wait_for(case, [job_id], timeout=35)
            raise ValueError("Acceptance wait limit reached; the saved fixture and receipt can be resumed.")
    conn = db.connect(case)
    try:
        row = db.one(conn, "SELECT state FROM jobs WHERE id=?", (job_id,))
    finally:
        conn.close()
    if not row or row["state"] != "done":
        raise ValueError("The OpenCTI job did not finish successfully; inspect the saved transfer receipt.")


def run(workspace_root, *, transfer=False, sample=False, offline=False, resume=None,
        output_root=None, wait_seconds=180, emit=_emit):
    if sample and not transfer:
        raise ValueError("--sample requires --transfer.")
    if offline and (transfer or resume):
        raise ValueError("--offline cannot transfer or resume remote work.")
    if resume and not transfer:
        raise ValueError("--resume requires --transfer.")
    proof = {"state": "preparing", "synthetic": True, "external_enrichment": False}
    if not offline:
        result = service.connection_test(workspace_root)
        if transfer and not result["capabilities"]["transfer"]:
            raise ValueError("Internal enrichment connectors must be manual before synthetic transfer.")
        proof["connection"] = {"ok": result["ok"], "version": result["version"]}
    if resume:
        case = Path(resume).resolve()
        marker = json.loads((case / _MARKER).read_text(encoding="utf-8"))
        if marker.get("schema") != 1 or not str(marker.get("reference", "")).startswith("PIM-QA-"):
            raise ValueError("Only an existing synthetic OpenCTI acceptance fixture can be resumed.")
        if workspace.case_info(case)["reference"] != marker["reference"]:
            raise ValueError("Synthetic fixture identity changed; refusing to resume.")
    else:
        output_root = output_root or Path(__file__).resolve().parent.parent / ".shellhound" / "opencti-smoke"
        case = _fixture(output_root)
        marker = json.loads((case / _MARKER).read_text(encoding="utf-8"))
    proof.update(case_reference=marker["reference"], fixture_dir=str(case))
    try:
        options = {"include_notes": True, "include_evidence": True, "indicator_ids": [marker["hash_id"]]}
        preview = graph.build_preview(case, options) if offline else service.preview(workspace_root, case, options)
        if sample:
            options["sample_ids"] = [s["id"] for s in preview["samples"] if s["available"]]
            preview = service.preview(workspace_root, case, options)
        if preview["errors"]:
            raise ValueError("Synthetic preview has errors: " + " ".join(preview["errors"]))
        _write(case / "opencti-preview.json", preview)
        proof["preview"] = {"iocs": len(preview["iocs"]), "relationships": len(preview["relationships"]),
                            "objects": len(preview["objects"]), "fingerprint": preview["fingerprint"]}
        expected_types = {"ip", "domain", "url", "email", "path", "user", "hash", "other"}
        expected_links = {"hash-of", "requested", "host-in", "account-of"}
        if not expected_types <= {r["type"] for r in preview["iocs"]} or not expected_links <= {r["kind"] for r in preview["relationships"]}:
            raise ValueError("Synthetic fixture graph is incomplete.")
        if not offline:
            client = OpenCTIClient(service._config(workspace_root))
            proof["lookup_matches"] = {r["type"]: len(client.lookup(r["type"], r["value"]))
                                       for r in preview["iocs"] if r["type"] not in ("path", "user", "other")}
        if transfer:
            pending = marker.get("export_id") if resume else None
            result = service.retry(workspace_root, case, pending) if pending else service.transfer(workspace_root, case, preview["preview_id"])
            marker["export_id"] = result["export_id"]
            _write(case / _MARKER, marker)
            emit({"stage": "transfer", "case_reference": marker["reference"], "export_id": result["export_id"]})
            _wait(case, result["job_id"], wait_seconds, emit)
            state = service.state(workspace_root, case)
            receipt = next(r for r in state["exports"] if r["id"] == result["export_id"])
            proof["export"] = receipt
            proof["state"] = "complete" if receipt["state"] == "complete" else "pending"
        else:
            proof["state"] = "offline-preview" if offline else "read-only-checks-complete"
    except Exception as exc:
        proof.update(state="failed", error=service._error(exc))
    _write(case / "opencti-proof.json", proof)
    emit(proof)
    return proof


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Config().workspace,
                        help="Existing workspace whose saved OpenCTI configuration is used")
    parser.add_argument("--offline", action="store_true", help="Build and validate a local fixture without networking")
    parser.add_argument("--transfer", action="store_true", help="Import the synthetic fixture into configured OpenCTI")
    parser.add_argument("--sample", action="store_true", help="Also upload the inert fixture bytes (requires saved sample-upload setting)")
    parser.add_argument("--resume", type=Path, help="Resume a pending fixture using its saved export receipt")
    parser.add_argument("--wait-seconds", type=int, default=180)
    args = parser.parse_args(argv)
    if not 1 <= args.wait_seconds <= 3600:
        parser.error("--wait-seconds must be between 1 and 3600")
    try:
        result = run(args.workspace, transfer=args.transfer, sample=args.sample, offline=args.offline,
                     resume=args.resume, wait_seconds=args.wait_seconds)
    except Exception as exc:
        _emit({"state": "failed", "error": service._error(exc)})
        return 1
    return 0 if result["state"] in ("complete", "offline-preview", "read-only-checks-complete") else 2


if __name__ == "__main__":
    raise SystemExit(main())
