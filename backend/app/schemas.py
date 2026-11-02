from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------
# LogEvent Schemas
# ---------------------------------------------------------
class LogEventBase(BaseModel):
    source: str = Field(..., description="Source system: ssh, web, firewall")
    raw: str = Field(..., description="Raw log entry text")
    src_ip: Optional[str] = Field(None, description="Source IP address")
    user: Optional[str] = Field(None, description="Target or authenticating user")
    event_type: str = Field(..., description="Normalized event type (e.g. login_failed, sql_injection)")
    status: str = Field("unknown", description="Status (success, failed, blocked, allowed)")
    extra: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Arbitrary additional metadata")


class LogEventCreate(LogEventBase):
    timestamp: Optional[datetime] = None


class LogEventRead(LogEventBase):
    id: int
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------
# Alert Schemas
# ---------------------------------------------------------
class AlertBase(BaseModel):
    rule_id: str
    rule_name: str
    severity: str = Field(..., description="low, medium, high, critical")
    mitre_technique_id: str
    mitre_technique_name: str
    mitre_tactic: str
    src_ip: Optional[str] = None
    user: Optional[str] = None
    description: str
    log_event_ids: List[int] = Field(default_factory=list)
    incident_id: Optional[int] = None


class AlertCreate(AlertBase):
    timestamp: Optional[datetime] = None


class AlertRead(AlertBase):
    id: int
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------
# ResponseAction Schemas
# ---------------------------------------------------------
class ResponseActionBase(BaseModel):
    incident_id: int
    action_type: str = Field(..., description="block_ip, disable_user, create_ticket")
    target: str = Field(..., description="Target entity (IP address, username, ticket title)")
    status: str = Field("pending", description="pending, executed, failed")
    details: Optional[str] = None


class ResponseActionCreate(ResponseActionBase):
    performed_at: Optional[datetime] = None


class ResponseActionRead(ResponseActionBase):
    id: int
    performed_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------
# Incident Schemas
# ---------------------------------------------------------
class IncidentBase(BaseModel):
    title: str
    severity: str = Field(..., description="low, medium, high, critical")
    status: str = Field("open", description="open, investigating, contained, closed")
    src_ip: Optional[str] = None
    affected_users: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    ai_summary: Optional[str] = None
    ai_recommendations: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    ai_generated_at: Optional[datetime] = None


class IncidentCreate(IncidentBase):
    pass


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    src_ip: Optional[str] = None
    affected_users: Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    ai_summary: Optional[str] = None
    ai_recommendations: Optional[List[Dict[str, Any]]] = None
    ai_generated_at: Optional[datetime] = None


class IncidentRead(IncidentBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IncidentDetailRead(IncidentRead):
    alerts: List[AlertRead] = Field(default_factory=list)
    response_actions: List[ResponseActionRead] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------
# Simulation Tables Schemas (Firewall, Identity, Ticketing)
# ---------------------------------------------------------
class BlockedIPBase(BaseModel):
    ip_address: str
    reason: Optional[str] = None
    incident_id: Optional[int] = None
    status: str = "active"


class BlockedIPCreate(BlockedIPBase):
    pass


class BlockedIPRead(BlockedIPBase):
    id: int
    blocked_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DisabledUserBase(BaseModel):
    username: str
    reason: Optional[str] = None
    incident_id: Optional[int] = None
    status: str = "disabled"


class DisabledUserCreate(DisabledUserBase):
    pass


class DisabledUserRead(DisabledUserBase):
    id: int
    disabled_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TicketBase(BaseModel):
    ticket_number: str
    title: str
    description: str
    severity: str = "medium"
    status: str = "open"
    incident_id: Optional[int] = None


class TicketCreate(TicketBase):
    pass


class TicketRead(TicketBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

