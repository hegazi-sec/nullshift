from pydantic import BaseModel
from typing import Optional, List, Any, Dict


class ChatRequest(BaseModel):
    message: str
    alert_id: Optional[str] = None
    agent_id: Optional[str] = None
    conversation_id: Optional[str] = None
    debug: Optional[bool] = False
    # New optional field-agnostic Wazuh search inputs
    search_field: Optional[str] = None
    search_value: Optional[str] = None
    # Default widened to 24h to reduce empty-result surprises
    time_range: Optional[str] = "last_24h"


class ChatResponse(BaseModel):
    what_happened: str
    why_it_matters: str
    evidence_pulled: List[Any]
    severity: str
    confidence: str
    l1_next_steps: List[str]
    escalate_to_l2_if: List[str]
    ticket_summary: str
    missing_evidence: Optional[List[str]] = []


# New multi-chat API schemas
class ConversationCreate(BaseModel):
    title: Optional[str] = None


class MessageCreate(BaseModel):
    message: str = ""
    debug: Optional[bool] = False
    images: Optional[List[str]] = None  # base64 data URLs, e.g. "data:image/png;base64,..."


# Tool execution schemas (admin/debug endpoint and internal typing)
class ToolExecuteRequest(BaseModel):
    tool_name: str
    query_id: str
    params: Optional[Dict[str, Any]] = None
    earliest: Optional[str] = None
    latest: Optional[str] = None


class ToolExecuteResponse(BaseModel):
    tool_name: str
    query_id: str
    result_count: int
    summary: Dict[str, Any]
    samples: List[Any]


class PrefsUpdate(BaseModel):
    prefs: Dict[str, Any]
