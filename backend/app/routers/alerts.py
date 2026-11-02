from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Alert
from ..schemas import AlertCreate, AlertRead

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


@router.get("", response_model=List[AlertRead], summary="Get detection alerts")
def list_alerts(
    limit: int = Query(100, ge=1, le=1000, description="Max alerts to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    severity: Optional[str] = Query(None, description="Filter by severity (low, medium, high, critical)"),
    rule_id: Optional[str] = Query(None, description="Filter by rule ID"),
    incident_id: Optional[int] = Query(None, description="Filter by linked incident ID"),
    src_ip: Optional[str] = Query(None, description="Filter by source IP"),
    user: Optional[str] = Query(None, description="Filter by targeted user"),
    db: Session = Depends(get_db),
) -> List[Alert]:
    query = db.query(Alert)

    if severity:
        query = query.filter(Alert.severity == severity.lower())
    if rule_id:
        query = query.filter(Alert.rule_id == rule_id)
    if incident_id is not None:
        query = query.filter(Alert.incident_id == incident_id)
    if src_ip:
        query = query.filter(Alert.src_ip == src_ip)
    if user:
        query = query.filter(Alert.user == user)

    return query.order_by(Alert.timestamp.desc()).offset(offset).limit(limit).all()


@router.post("", response_model=AlertRead, status_code=status.HTTP_201_CREATED, summary="Create an alert")
def create_alert(
    alert_in: AlertCreate,
    db: Session = Depends(get_db),
) -> Alert:
    alert_data = alert_in.model_dump(exclude_unset=True)
    db_alert = Alert(**alert_data)
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    return db_alert

