"""Case-scoped HTTP boundaries for locally registered log evidence."""
from pathlib import Path
from fastapi import HTTPException
from pydantic import BaseModel, Field

from server import db, log_evidence, source_time
from server.events import hub
from server.jobs import CaseBusy


def install(app, auth, case_dir_or_404, manager):
    class PreviewBody(BaseModel):
        path: str
        timezone: str = 'auto'

    @app.get('/api/timezones', dependencies=[auth])
    def timezones():
        return source_time.catalogue()

    class SettingsBody(BaseModel):
        format: str = "auto"
        timezone: str = ""
        label: str = ""
        server_root: str = ""
        webroot: str = ""

    class AnalyzeBody(BaseModel):
        source_ids: list[str] | None = None

    class RegisterBody(BaseModel):
        path: str
        label: str = Field(default="", max_length=120)
        timezone: str = ""
        formats: dict[str, str] = Field(default_factory=dict)

    class Selection(BaseModel):
        id: str
        fingerprint: str = Field(min_length=64, max_length=64)

    class ApplyBody(BaseModel):
        selections: list[Selection] = Field(min_length=1, max_length=200)
        note: str = Field(default="", max_length=2000)

    def change(slug, fn):
        directory = case_dir_or_404(slug)
        try:
            with manager.case_operation(directory):
                result = fn(directory)
            hub.publish({"type": "invalidate", "scope": "logs", "case_slug": slug})
            return result
        except (CaseBusy, log_evidence.LogEvidenceError) as exc:
            raise HTTPException(409, str(exc)) from None
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None

    @app.post("/api/cases/{slug}/log-sources/preview", dependencies=[auth])
    def preview(slug: str, body: PreviewBody):
        case_dir_or_404(slug)
        if not Path(body.path).exists():
            raise HTTPException(400, "Choose an existing log file or folder")
        try:
            return log_evidence.preview(body.path, source_time.validate(body.timezone))
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None

    @app.get("/api/cases/{slug}/log-sources", dependencies=[auth])
    def sources(slug: str):
        try:
            return {"sources": log_evidence.source_status(case_dir_or_404(slug)),
                    "formats": log_evidence.parsers.FORMATS}
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None

    @app.post("/api/cases/{slug}/log-sources/register", dependencies=[auth])
    def register(slug: str, body: RegisterBody):
        def save(case):
            if not Path(body.path).exists():
                raise ValueError("Choose an existing log file or folder")
            options = log_evidence.validate_settings({"timezone": body.timezone})
            preview = log_evidence.preview(body.path)["sources"]
            if set(body.formats) - {s["id"] for s in preview}:
                raise ValueError("The selected files changed; preview them again")
            for fmt in body.formats.values():
                log_evidence.validate_settings({"format": fmt})
            conn = db.connect(case)
            try:
                conn.execute("INSERT OR IGNORE INTO evidence(kind,path,added,label) VALUES ('logs',?,?,?)",
                             (str(Path(body.path)), db.now(), body.label))
                conn.commit()
            finally:
                conn.close()
            sources = log_evidence.inventory(case, persist=True)
            ids = {s["id"] for s in preview}
            for source in sources:
                if source["id"] in ids:
                    log_evidence.configure(case, source["id"], {**options, **source["settings"],
                        "timezone": body.timezone or source["settings"].get("timezone", ""),
                        "label": body.label if len(ids) == 1 and body.label else source["settings"].get("label", ""),
                        "format": body.formats.get(source["id"], source["settings"].get("format", "auto"))}, source=source)
            return {"registered": len(ids)}
        return change(slug, save)

    @app.patch("/api/cases/{slug}/log-sources/{source_id}", dependencies=[auth])
    def settings(slug: str, source_id: str, body: SettingsBody):
        return change(slug, lambda case: log_evidence.configure(case, source_id, body.model_dump()))

    @app.post("/api/cases/{slug}/log-sources/analyze", dependencies=[auth])
    def analyze(slug: str, body: AnalyzeBody):
        def submit(case):
            current = log_evidence.inventory(case)
            if body.source_ids is not None and (not body.source_ids or set(body.source_ids) - {s["id"] for s in current}):
                raise log_evidence.LogEvidenceError("Choose currently registered sources")
            if body.source_ids and any(s["format"] == "access" and s["id"] in body.source_ids for s in current):
                raise log_evidence.LogEvidenceError("Access logs share the HTTP index. Use Run analysis in Evidence to rebuild it")
            return {"job": manager.submit(case, "log_events", lambda ctx: log_evidence.build(case, ctx, body.source_ids),
                                          scan_context={"mode": "log_retry"})}
        return change(slug, submit)

    @app.post("/api/cases/{slug}/log-sources/{source_id}/accept-warning", dependencies=[auth])
    def accept(slug: str, source_id: str):
        return change(slug, lambda case: log_evidence.accept_warning(case, source_id))

    @app.post("/api/cases/{slug}/log-events/search", dependencies=[auth])
    def search(slug: str, body: dict):
        try:
            return log_evidence.search(case_dir_or_404(slug), body)
        except (ValueError, TypeError, OverflowError) as exc:
            raise HTTPException(400, "Invalid log filter") from exc

    @app.get("/api/cases/{slug}/log-events/{event_id}/context", dependencies=[auth])
    def context(slug: str, event_id: str, fingerprint: str = ""):
        try:
            return log_evidence.context(case_dir_or_404(slug), event_id, fingerprint)
        except (ValueError, OSError) as exc:
            raise HTTPException(409, str(exc) if isinstance(exc, ValueError) else "The source is unavailable") from None

    @app.post("/api/cases/{slug}/log-events/apply", dependencies=[auth])
    def apply(slug: str, body: ApplyBody):
        return change(slug, lambda case: log_evidence.apply(case, [s.model_dump() for s in body.selections], body.note))
