"""Local IOC detail and analyst assertion endpoints."""
from fastapi import HTTPException
from contextlib import ExitStack
from pydantic import BaseModel, Field, StrictInt
from server import db
from server.jobs import CaseBusy
from server.ioc import model as ioc_model


class AssessmentBody(BaseModel):
    state: str
    reason: str = Field(min_length=1, max_length=10000)


class RelationshipBody(BaseModel):
    src: int
    dst: int
    kind: str
    reference: str = Field(min_length=1, max_length=2000)
    detail: str = Field(default="", max_length=10000)
    observation_id: str | None = None
    first_seen: str = ""
    last_seen: str = ""


class WithdrawalBody(BaseModel):
    reason: str = Field(min_length=1, max_length=10000)


class TagsBody(BaseModel):
    add: list[str] = Field(default_factory=list, max_length=100)
    remove: list[str] = Field(default_factory=list, max_length=100)


class DeleteObjectsBody(BaseModel):
    ids: list[StrictInt] = Field(min_length=1, max_length=10000)


class EditObjectBody(BaseModel):
    value: str = Field(min_length=1, max_length=8192)
    note: str = Field(max_length=10000)
    expected_value: str
    expected_note: str
    assessment: str
    expected_assessment: str
    reason: str = Field(default="", max_length=2000)
    add_tags: list[str] = Field(default_factory=list, max_length=100)
    remove_tags: list[str] = Field(default_factory=list, max_length=100)


def register(app, resolve_case, auth, hub):
    def run(slug, action, *, write=False, content_ioc=None):
        conn = db.connect(resolve_case(slug))
        operation = ExitStack()
        try:
            if content_ioc is not None:
                item = db.one(conn, 'SELECT type FROM iocs WHERE id=?', (content_ioc,))
                if item and item['type'] in ('file', 'hash'):
                    from server.jobs import manager
                    operation.enter_context(manager.case_operation(resolve_case(slug)))
            if write:
                conn.execute("BEGIN IMMEDIATE")
            result = action(conn)
            if write:
                # Only newly recorded explicit file/hash assessments seed content
                # reuse. Default IOC badges never become analyst decisions.
                from server import backups
                changed = backups.seed_ioc_assessments(conn)
                if changed:
                    content = backups.inherit_all(conn, digests=changed)
                    if result is None:
                        result = {'ok': True}
                    if isinstance(result, dict):
                        result['content_assessment'] = content
                conn.commit()
                hub.publish({"type": "invalidate", "scope": "iocs"})
                if changed:
                    hub.publish({"type": "invalidate", "scope": "findings"})
            return result
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from None
        except CaseBusy as exc:
            raise HTTPException(409, str(exc)) from None
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        finally:
            conn.close()
            operation.close()

    @app.get("/api/cases/{slug}/iocs/{ioc_id}/detail", dependencies=[auth])
    def detail(slug: str, ioc_id: int):
        return run(slug, lambda conn: ioc_model.detail(conn, ioc_id))

    @app.post("/api/cases/{slug}/iocs/{ioc_id}/cve", dependencies=[auth])
    def public_cve(slug: str, ioc_id: int):
        from server.integrations.cve import fetch_record
        def load(conn):
            item = ioc_model.detail(conn, ioc_id)["object"]
            if item["type"] != "vulnerability":
                raise ValueError("Public CVE lookup requires a vulnerability object.")
            return fetch_record(item["value"])
        return run(slug, load)

    @app.post("/api/cases/{slug}/iocs/delete", dependencies=[auth])
    def delete_selected(slug: str, body: DeleteObjectsBody):
        return run(slug, lambda conn: ioc_model.delete_objects(conn, body.ids), write=True)

    @app.post("/api/cases/{slug}/iocs/{ioc_id}/tags", dependencies=[auth])
    def tags(slug: str, ioc_id: int, body: TagsBody):
        return run(slug, lambda conn: ioc_model.edit_tags(conn, ioc_id, body.add, body.remove), write=True)

    @app.post("/api/cases/{slug}/iocs/{ioc_id}/edit", dependencies=[auth])
    def edit(slug: str, ioc_id: int, body: EditObjectBody):
        return run(slug, lambda conn: ioc_model.edit_object(conn, ioc_id, **body.model_dump()), write=True, content_ioc=ioc_id)

    @app.post("/api/cases/{slug}/iocs/{ioc_id}/assessments", dependencies=[auth])
    def assess(slug: str, ioc_id: int, body: AssessmentBody):
        return run(slug, lambda conn: ioc_model.assess(conn, ioc_id, body.state, body.reason), write=True, content_ioc=ioc_id)

    @app.post("/api/cases/{slug}/iocs/{ioc_id}/verify-file", dependencies=[auth])
    def verify_file(slug: str, ioc_id: int):
        return run(slug, lambda conn: ioc_model.verify_file(conn, ioc_id), write=True)

    @app.post("/api/cases/{slug}/ioc-relationships", dependencies=[auth])
    def relate(slug: str, body: RelationshipBody):
        return run(slug, lambda conn: {"id": ioc_model.relationship(conn, **body.model_dump())}, write=True)

    @app.post("/api/cases/{slug}/ioc-relationships/{link_id}/withdraw", dependencies=[auth])
    def withdraw(slug: str, link_id: int, body: WithdrawalBody):
        return run(slug, lambda conn: ioc_model.withdraw(conn, link_id, body.reason), write=True)
