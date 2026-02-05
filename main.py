from fastapi import FastAPI
from  pydantic import BaseModel
from typing import Dict, List, Optional
app = FastAPI()

class IncomingMessage(BaseModel):
    sessionId : str
    message : Dict
    conversationHistory : Optional[List[Dict]]
    metadata : Optional[Dict]


@app.post("/")
async def root(message : IncomingMessage):
    return{"status" : "success", "reply" : "Why will my account be blocked?"}