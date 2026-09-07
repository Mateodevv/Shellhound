"""Local IOC detail and analyst assertion endpoints."""
from fastapi import HTTPException
from pydantic import BaseModel, Field
from server import db, ioc_model


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


def register(app, resolve_case, auth, hub):
    def run(slug, action, *, write=False):
        conn = db.connect(resolve_case(slug))
        try:
            if write:
                conn.execute("BEGIN IMMEDIATE")
            result = action(conn)
            if write:
                conn.commit()
                hub.publish({"type": "invalidate", "scope": "iocs"})
            return result
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from None
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        finally:
            conn.close()

    @app.get("/api/cases/{slug}/iocs/{ioc_id}/detail", dependencies=[auth])
    def detail(slug: str, ioc_id: int):
        return run(slug, lambda conn: ioc_model.detail(conn, ioc_id))

    @app.post("/api/cases/{slug}/iocs/{ioc_id}/assessments", dependencies=[auth])
    def assess(slug: str, ioc_id: int, body: AssessmentBody):
        return run(slug, lambda conn: ioc_model.assess(conn, ioc_id, body.state, body.reason), write=True)

    @app.post("/api/cases/{slug}/iocs/{ioc_id}/verify-file", dependencies=[auth])
    def verify_file(slug: str, ioc_id: int):
        return run(slug, lambda conn: ioc_model.verify_file(conn, ioc_id), write=True)

    @app.post("/api/cases/{slug}/ioc-relationships", dependencies=[auth])
    def relate(slug: str, body: RelationshipBody):
        return run(slug, lambda conn: {"id": ioc_model.relationship(conn, **body.model_dump())}, write=True)

    @app.post("/api/cases/{slug}/ioc-relationships/{link_id}/withdraw", dependencies=[auth])
    def withdraw(slug: str, link_id: int, body: WithdrawalBody):
        return run(slug, lambda conn: ioc_model.withdraw(conn, link_id, body.reason), write=True)
