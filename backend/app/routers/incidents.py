from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session, selectinload

from ..db import get_db
from ..models import Incident
from ..schemas import IncidentCreate, IncidentDetailRead, IncidentRead, IncidentUpdate

router = APIRouter(prefix="/api/incidents", tags=["Incidents"])


@router.get("", response_model=List[IncidentRead], summary="Get correlated incidents")
def list_incidents(
    limit: int = Query(100, ge=1, le=1000, description="Max incidents to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (open, investigating, contained, closed)"),
    severity: Optional[str] = Query(None, description="Filter by severity (low, medium, high, critical)"),
    src_ip: Optional[str] = Query(None, description="Filter by primary attacker IP"),
    db: Session = Depends(get_db),
) -> List[Incident]:
    query = db.query(Incident)

    if status_filter:
        query = query.filter(Incident.status == status_filter.lower())
    if severity:
        query = query.filter(Incident.severity == severity.lower())
    if src_ip:
        query = query.filter(Incident.src_ip == src_ip)

    return query.order_by(Incident.created_at.desc()).offset(offset).limit(limit).all()


@router.get("/{id}", response_model=IncidentDetailRead, summary="Get incident details by ID")
def get_incident(
    id: int,
    db: Session = Depends(get_db),
) -> Incident:
    incident = (
        db.query(Incident)
        .options(selectinload(Incident.alerts), selectinload(Incident.response_actions))
        .filter(Incident.id == id)
        .first()
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID {id} not found"
        )
    return incident


@router.post("", response_model=IncidentRead, status_code=status.HTTP_201_CREATED, summary="Create an incident")
def create_incident(
    incident_in: IncidentCreate,
    db: Session = Depends(get_db),
) -> Incident:
    incident_data = incident_in.model_dump(exclude_unset=True)
    db_incident = Incident(**incident_data)
    db.add(db_incident)
    db.commit()
    db.refresh(db_incident)
    return db_incident


@router.patch("/{id}", response_model=IncidentDetailRead, summary="Update an incident")
def update_incident(
    id: int,
    incident_in: IncidentUpdate,
    db: Session = Depends(get_db),
) -> Incident:
    incident = (
        db.query(Incident)
        .options(selectinload(Incident.alerts), selectinload(Incident.response_actions))
        .filter(Incident.id == id)
        .first()
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID {id} not found"
        )

    update_data = incident_in.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(incident, field, value)

    db.commit()
    db.refresh(incident)
    return incident

