from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import LogEvent
from ..schemas import LogEventCreate, LogEventRead

router = APIRouter(prefix="/api/logs", tags=["Logs"])


@router.get("", response_model=List[LogEventRead], summary="Get log events")
def list_logs(
    limit: int = Query(100, ge=1, le=1000, description="Max logs to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    source: Optional[str] = Query(None, description="Filter by source (e.g. ssh, web, firewall)"),
    src_ip: Optional[str] = Query(None, description="Filter by source IP"),
    user: Optional[str] = Query(None, description="Filter by user"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status"),
    db: Session = Depends(get_db),
) -> List[LogEvent]:
    query = db.query(LogEvent)

    if source:
        query = query.filter(LogEvent.source == source)
    if src_ip:
        query = query.filter(LogEvent.src_ip == src_ip)
    if user:
        query = query.filter(LogEvent.user == user)
    if event_type:
        query = query.filter(LogEvent.event_type == event_type)
    if status_filter:
        query = query.filter(LogEvent.status == status_filter)

    return query.order_by(LogEvent.timestamp.desc()).offset(offset).limit(limit).all()


@router.post("", response_model=LogEventRead, status_code=status.HTTP_201_CREATED, summary="Create/Ingest single log event")
def create_log(
    log_in: LogEventCreate,
    db: Session = Depends(get_db),
) -> LogEvent:
    log_data = log_in.model_dump(exclude_unset=True)
    db_log = LogEvent(**log_data)
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log

