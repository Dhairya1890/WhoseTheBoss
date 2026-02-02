from pydantic import BaseModel, Field
from typing import Optional, List
from uuid import UUID, uuid4
from datetime import datetime




class User(BaseModel):
    id:Optional[UUID] = Field(default_factory=uuid4)
    name:str
    message:str
    timestamp:datetime

class Messages(BaseModel):
    id:Optional[UUID] = Field(default_factory=uuid4)
    message:str
    timestamp:datetime = None


class ChatSession(BaseModel):
    session_id: UUID = Field(default_factory=uuid4)
    messages: List[Messages]
