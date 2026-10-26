from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app import models
from app.database import get_db
from app.services.device_access import require_control
from app.services import console_workflow as workflow

router = APIRouter(prefix="/console", tags=["Console workflow"])

class StartInput(BaseModel):
    asset_id: int = Field(default=0, ge=0)

@router.post("/start", dependencies=[Depends(require_control)])
def start(payload: StartInput, db: Session = Depends(get_db)):
    with workflow.lock:
        row, reused = workflow.acquire(db, payload.asset_id)
        if not reused:
            workflow.launch(row.id)
        return {"workflow": workflow.payload(db, row), "reused": reused}

@router.get("/current")
def current(db: Session = Depends(get_db)):
    with workflow.lock:
        row = db.query(models.ConsoleWorkflow).order_by(models.ConsoleWorkflow.created_at.desc()).first()
        return {"workflow": workflow.payload(db, row) if row else None}
