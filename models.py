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
    """Enum representing the type of message sender."""
    SCAMMER = "scammer"
    USER = "user"
    AGENT = "agent"


class ChannelType(str, Enum):
    """Enum representing supported communication channels."""
    SMS = "SMS"
    WHATSAPP = "Whatsapp"
    EMAIL = "Email"
    TELEGRAM = "Telegram"


class Message(BaseModel):
    """Represents a single message in the conversation."""
    sender: SenderType
    text: str
    timestamp: int


class MetaData(BaseModel):
    """Metadata associated with the conversation."""
    channel: ChannelType
    language: str = "English"
    locale: str = "IN"


class IncomingMessageRequest(BaseModel):
    """Data model for incoming messages from suspected scammers."""
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: MetaData

    def is_first_message(self) -> bool:
        """Check if this is the first message in the conversation."""
        return len(self.conversationHistory) == 0

    def get_full_conversation(self) -> List[Message]:
        """Get the full conversation including the current message."""
        return self.conversationHistory + [self.message]

    def get_message_count(self) -> int:
        """Get the total number of messages including the current one."""
        return len(self.conversationHistory) + 1


# Alias for backward compatibility
ConversationRequest = IncomingMessageRequest


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
