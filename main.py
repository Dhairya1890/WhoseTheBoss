from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from models import Messages  # Only import what you use
from uuid import UUID, uuid4
from datetime import datetime
from typing import List, Dict
from auth import get_api_key

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

Chat_Session: Dict[UUID, List[Dict]] = {}

@app.get('/')
def read_root():
    return {"Status": "Healthy"}

@app.get('/api/v1/start_session', dependencies=[Depends(get_api_key)])
async def start_session():
    # Create a chat id
    session_id = uuid4()
    Chat_Session[session_id] = []
    return {"session_id": session_id}

@app.post('/api/v1/{session_id}/message', dependencies=[Depends(get_api_key)])
async def add_message(session_id: UUID, message: Messages):
    if session_id not in Chat_Session:
        raise HTTPException(status_code=404, detail="Session not found")
    if message.timestamp is None:
        message.timestamp = datetime.now()
    
    Chat_Session[session_id].append(message.model_dump())
    return {"status": "success", "message": message}

@app.get('/api/v1/history/{session_id}', dependencies=[Depends(get_api_key)])  # FIXED: app -> api
async def get_history(session_id: UUID):
    if session_id not in Chat_Session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"session_id": session_id, "messages": Chat_Session[session_id]}

@app.get('/api/v1/all_sessions_list', dependencies=[Depends(get_api_key)])
async def get_all_sessions():
    # FIXED: Convert UUIDs to strings for JSON serialization
    return {"chat_sessions": [str(session_id) for session_id in Chat_Session.keys()]}