from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from uuid import UUID, uuid4
from datetime import datetime
from enum import Enum


class Messages(BaseModel):
    id: Optional[UUID] = Field(default_factory=uuid4)
    message: str
    timestamp: datetime = None


class ChatSession(BaseModel):
    session_id: UUID = Field(default_factory=uuid4)
    messages: List[Messages]


class SenderType(str, Enum):
    SCAMMER = "scammer"
    USER = "user"
    AGENT = "agent"


class Channel(str, Enum):
    SMS = "SMS"
    WHATSAPP = "Whatsapp"
    EMAIL = "Email"
    TELEGRAM = "Telegram"


class Message(BaseModel):
    sender: str
    text: str
    timestamp: int


class MetaData(BaseModel):
    channel: str
    language: str
    locale: str


class ConversationRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: MetaData


class ExtractedIntelligence(BaseModel):
    bankAccounts: List[str] = []
    upiIds: List[str] = []
    phishingLinks: List[str] = []
    phoneNumbers: List[str] = []
    suspiciousKeywords: List[str] = []


class ScamAnalysis(BaseModel):
    sessionId: str
    scamDetected: bool
    totalMessagesExchanged: int
    extractedIntelligence: ExtractedIntelligence
    agentNotes: str


class AgentResponse(BaseModel):
    shouldEngage: bool
    responseText: Optional[str] = None
    strategy: Optional[str] = None


class Intelligence(BaseModel):
    phoneNumbers: List[str] = []
    urls: List[str] = []
    upiIds: List[str] = []
    tactics: List[str] = []
    keywords: List[str] = []


class CallbackPayload(BaseModel):
    sessionId: str
    scamDetected: bool
    totalMessagesExchanged: int
    extractedIntelligence: ExtractedIntelligence
    agentNotes: str


class IncomingMessage(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[MetaData] = None
