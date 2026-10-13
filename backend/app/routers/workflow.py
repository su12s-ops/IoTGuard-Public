from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.agent_intelligence import (
    build_behavior_chains,
    build_business_reconstruction,
    build_dependency_topology,
    build_four_agent_workflow,
)

router = APIRouter(prefix="/workflow", tags=["Agent Workflow"])


@router.get("/overview")
def overview(db: Session = Depends(get_db)):
    return build_four_agent_workflow(db)


@router.get("/dependency-graph")
def dependency_graph(db: Session = Depends(get_db)):
    return build_dependency_topology(db)


@router.get("/behavior-chains")
def behavior_chains(db: Session = Depends(get_db)):
    return build_behavior_chains(db)


@router.get("/business-reconstruction")
def business_reconstruction(db: Session = Depends(get_db)):
    return build_business_reconstruction(db)
