from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import BlockedIP, DisabledUser, Ticket
from ..schemas import (
    BlockedIPCreate,
    BlockedIPRead,
    DisabledUserCreate,
    DisabledUserRead,
    TicketCreate,
    TicketRead,
)

router = APIRouter(prefix="/api/simulations", tags=["Simulated Systems"])


# ---------------------------------------------------------
# Blocked IPs (Firewall)
# ---------------------------------------------------------
@router.get("/blocked-ips", response_model=List[BlockedIPRead], summary="List blocked IPs")
def list_blocked_ips(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    status_filter: Optional[str] = Query(None, alias="status"),
    db: Session = Depends(get_db),
) -> List[BlockedIP]:
    query = db.query(BlockedIP)
    if status_filter:
        query = query.filter(BlockedIP.status == status_filter)
    return query.order_by(BlockedIP.blocked_at.desc()).offset(offset).limit(limit).all()


@router.post("/blocked-ips", response_model=BlockedIPRead, status_code=status.HTTP_201_CREATED, summary="Add blocked IP")
def create_blocked_ip(
    ip_in: BlockedIPCreate,
    db: Session = Depends(get_db),
) -> BlockedIP:
    db_obj = BlockedIP(**ip_in.model_dump(exclude_unset=True))
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return db_obj


# ---------------------------------------------------------
# Disabled Users (Identity System)
# ---------------------------------------------------------
@router.get("/disabled-users", response_model=List[DisabledUserRead], summary="List disabled users")
def list_disabled_users(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    status_filter: Optional[str] = Query(None, alias="status"),
    db: Session = Depends(get_db),
) -> List[DisabledUser]:
    query = db.query(DisabledUser)
    if status_filter:
        query = query.filter(DisabledUser.status == status_filter)
    return query.order_by(DisabledUser.disabled_at.desc()).offset(offset).limit(limit).all()


@router.post("/disabled-users", response_model=DisabledUserRead, status_code=status.HTTP_201_CREATED, summary="Disable user")
def create_disabled_user(
    user_in: DisabledUserCreate,
    db: Session = Depends(get_db),
) -> DisabledUser:
    db_obj = DisabledUser(**user_in.model_dump(exclude_unset=True))
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return db_obj


# ---------------------------------------------------------
# Tickets (Ticketing System)
# ---------------------------------------------------------
@router.get("/tickets", response_model=List[TicketRead], summary="List response tickets")
def list_tickets(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    status_filter: Optional[str] = Query(None, alias="status"),
    db: Session = Depends(get_db),
) -> List[Ticket]:
    query = db.query(Ticket)
    if status_filter:
        query = query.filter(Ticket.status == status_filter)
    return query.order_by(Ticket.created_at.desc()).offset(offset).limit(limit).all()


@router.post("/tickets", response_model=TicketRead, status_code=status.HTTP_201_CREATED, summary="Create ticket")
def create_ticket(
    ticket_in: TicketCreate,
    db: Session = Depends(get_db),
) -> Ticket:
    db_obj = Ticket(**ticket_in.model_dump(exclude_unset=True))
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return db_obj

