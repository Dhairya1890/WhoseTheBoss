from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from models import (
    IncomingMessage,
    ExtractedIntelligence,
    CallbackPayload
)
from llm_service import llm_service
from typing import Dict, List, Optional
from datetime import datetime
import httpx
import re
import os

app = FastAPI(title="Scam Detection Pipeline")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"


class SessionManager:
    
    def __init__(self):
        self.sessions: Dict[str, Dict] = {}
    
    def get_or_create(self, session_id: str) -> Dict:
        if session_id not in self.sessions:
            self.sessions[session_id] = {
                "start_time": datetime.now(),
                "turn_count": 0,
                "scam_detected": False,
                "scam_type": None,
                "confidence": 0.0,
                "is_active": True,
                "conversation_history": [],
                "extracted_intelligence": {
                    "bankAccounts": [],
                    "upiIds": [],
                    "phishingLinks": [],
                    "phoneNumbers": [],
                    "suspiciousKeywords": []
                },
                "agent_notes": "",
                "callback_sent": False
            }
        return self.sessions[session_id]
    
    def update_session(self, session_id: str, updates: Dict):
        if session_id in self.sessions:
            self.sessions[session_id].update(updates)
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        return self.sessions.get(session_id)
    
    def delete_session(self, session_id: str):
        if session_id in self.sessions:
            del self.sessions[session_id]


class IntelligenceExtractor:
    
    def __init__(self):
        self.phone_pattern = re.compile(r'\+?91?\s*\d{10}|\b\d{10}\b')
        self.url_pattern = re.compile(r'http[s]?://[^\s]+')
        self.upi_pattern = re.compile(r'[\w\.\-]+@[a-zA-Z]+')
        self.bank_pattern = re.compile(r'\b\d{9,18}\b')
        
        self.scam_keywords = [
            "urgent", "immediately", "blocked", "suspended", "verify",
            "otp", "cvv", "pin", "account", "bank", "upi", "payment",
            "prize", "won", "lottery", "claim", "refund", "verify now"
        ]
    
    def extract_from_text(self, text: str) -> Dict:
        phones = list(set(self.phone_pattern.findall(text)))
        urls = list(set(self.url_pattern.findall(text)))
        upis = list(set(self.upi_pattern.findall(text)))
        banks = list(set(self.bank_pattern.findall(text)))
        
        text_lower = text.lower()
        keywords = [kw for kw in self.scam_keywords if kw in text_lower]
        
        return {
            "phoneNumbers": phones[:10],
            "phishingLinks": urls[:10],
            "upiIds": upis[:10],
            "bankAccounts": banks[:10],
            "suspiciousKeywords": list(set(keywords))[:15]
        }
    
    def merge_intelligence(self, existing: Dict, new: Dict) -> Dict:
        merged = {}
        for key in ["bankAccounts", "upiIds", "phishingLinks", "phoneNumbers", "suspiciousKeywords"]:
            existing_list = existing.get(key, [])
            new_list = new.get(key, [])
            merged[key] = list(set(existing_list + new_list))[:20]
        return merged


class ScamDetector:
    
    def __init__(self):
        self.critical_keywords = {
            "account blocked", "verify immediately", "share otp",
            "share cvv", "share pin", "account suspended",
            "urgent verification", "confirm password", "account terminated"
        }
        
        self.warning_keywords = {
            "verify", "urgent", "immediately", "account", "bank",
            "suspended", "blocked", "upi", "payment failed"
        }
        
        self.contextual_keywords = {
            "prize", "won", "lottery", "congratulations", "claim",
            "refund", "tax", "reward"
        }
        
        self.patterns = {
            "phone": re.compile(r'\b\d{10}\b'),
            "url": re.compile(r'http[s]?://[^\s]+'),
            "suspicious_url": re.compile(r'bit\.ly|tinyurl|short\.|goo\.gl'),
            "upi": re.compile(r'[\w\.\-]+@[\w]+')
        }
    
    def detect(self, text: str) -> Dict:
        text_lower = text.lower()
        
        confidence = 0.0
        indicators = []
        is_scam = False
        scam_type = None
        
        for keyword in self.critical_keywords:
            if keyword in text_lower:
                confidence += 0.8
                indicators.append(f"Critical: '{keyword}'")
                is_scam = True
                scam_type = "Banking Fraud"
                break
        
        if not is_scam:
            found_warnings = 0
            for keyword in self.warning_keywords:
                if keyword in text_lower:
                    confidence += 0.15
                    found_warnings += 1
                    indicators.append(f"Warning: '{keyword}'")
                    if found_warnings >= 3:
                        break
            
            if found_warnings >= 2:
                is_scam = True
                scam_type = "Phishing"
        
        if self.patterns["phone"].search(text):
            confidence += 0.1
            indicators.append("Contains phone number")
        
        if self.patterns["suspicious_url"].search(text):
            confidence += 0.2
            indicators.append("Suspicious URL shortener")
        elif self.patterns["url"].search(text):
            confidence += 0.05
            indicators.append("Contains URL")
        
        if self.patterns["upi"].search(text):
            confidence += 0.15
            indicators.append("Contains UPI ID pattern")
            if not scam_type:
                scam_type = "UPI Fraud"
        
        for keyword in self.contextual_keywords:
            if keyword in text_lower:
                confidence += 0.1
                indicators.append(f"Contextual: '{keyword}'")
                if not scam_type:
                    scam_type = "Lottery Scam" if keyword in ["prize", "won", "lottery"] else "Generic Fraud"
                break
        
        confidence = min(confidence, 1.0)
        is_scam = is_scam or confidence >= 0.3
        
        return {
            "is_scam": is_scam,
            "confidence": round(confidence, 2),
            "scam_type": scam_type if is_scam else None,
            "indicators": indicators[:5],
            "reasoning": self._generate_reasoning(is_scam, confidence, indicators)
        }
    
    def _generate_reasoning(self, is_scam: bool, confidence: float, indicators: List[str]) -> str:
        if not is_scam:
            return "No strong scam indicators detected"
        return f"Detected {len(indicators)} indicators with {confidence*100:.0f}% confidence"


session_manager = SessionManager()
intelligence_extractor = IntelligenceExtractor()
scam_detector = ScamDetector()


async def send_callback_to_guvi(session_id: str, session_data: Dict) -> bool:
    payload = {
        "sessionId": session_id,
        "scamDetected": session_data.get("scam_detected", True),
        "totalMessagesExchanged": session_data.get("turn_count", 0),
        "extractedIntelligence": session_data.get("extracted_intelligence", {}),
        "agentNotes": session_data.get("agent_notes", "Scam engagement completed")
    }
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                GUVI_CALLBACK_URL,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            return response.status_code == 200
    except Exception:
        return False


def should_send_callback(session_data: Dict) -> bool:
    if session_data.get("callback_sent", False):
        return False
    
    if not session_data.get("scam_detected", False):
        return False
    
    turn_count = session_data.get("turn_count", 0)
    if turn_count < 3:
        return False
    
    intelligence = session_data.get("extracted_intelligence", {})
    total_intel = sum(len(v) for v in intelligence.values() if isinstance(v, list))
    
    if turn_count >= 10 or total_intel >= 3:
        return True
    
    return False


def build_conversation_history(
    incoming_history: List[Dict],
    current_message: Dict
) -> List[Dict]:
    history = []
    
    for msg in incoming_history:
        history.append({
            "sender": msg.get("sender", "unknown"),
            "text": msg.get("text", ""),
            "timestamp": msg.get("timestamp", 0)
        })
    
    history.append({
        "sender": current_message.get("sender", "scammer"),
        "text": current_message.get("text", ""),
        "timestamp": current_message.get("timestamp", 0)
    })
    
    return history


@app.get("/")
async def health_check():
    return {"status": "healthy", "reply": "Can you tell me more about the issue?"}


@app.post("/")
async def process_message(request: IncomingMessage):
    session_id = request.sessionId
    message = request.message
    conversation_history = request.conversationHistory
    
    session_data = session_manager.get_or_create(session_id)
    
    message_text = message.get("text", "")
    
    full_history = build_conversation_history(conversation_history, message)
    session_data["conversation_history"] = full_history
    session_data["turn_count"] = len(full_history)
    
    new_intel = intelligence_extractor.extract_from_text(message_text)
    session_data["extracted_intelligence"] = intelligence_extractor.merge_intelligence(
        session_data["extracted_intelligence"],
        new_intel
    )
    
    if not session_data.get("scam_detected", False):
        detection_result = scam_detector.detect(message_text)
        
        if detection_result["is_scam"]:
            session_data["scam_detected"] = True
            session_data["scam_type"] = detection_result["scam_type"]
            session_data["confidence"] = detection_result["confidence"]
    
    if session_data.get("scam_detected", False):
        try:
            llm_intel = await llm_service.extract_intelligence_llm(full_history)
            session_data["extracted_intelligence"] = intelligence_extractor.merge_intelligence(
                session_data["extracted_intelligence"],
                llm_intel
            )
            if llm_intel.get("agentNotes"):
                session_data["agent_notes"] = llm_intel["agentNotes"]
        except Exception:
            pass
        
        try:
            agent_reply = await llm_service.generate_agent_response(
                scam_type=session_data.get("scam_type", "Phishing"),
                message=message_text,
                conversation_history=full_history,
                extracted_intelligence=session_data["extracted_intelligence"]
            )
        except Exception:
            agent_reply = get_fallback_response(
                session_data.get("scam_type"),
                session_data.get("turn_count", 0)
            )
    else:
        agent_reply = get_fallback_response(None, session_data.get("turn_count", 0))
    
    session_manager.update_session(session_id, session_data)
    
    if should_send_callback(session_data):
        callback_success = await send_callback_to_guvi(session_id, session_data)
        if callback_success:
            session_data["callback_sent"] = True
            session_manager.update_session(session_id, {"callback_sent": True})
    
    return {
        "status": "success",
        "reply": agent_reply
    }


@app.post("/analyze")
async def analyze_message(request: IncomingMessage):
    message_text = request.message.get("text", "")
    conversation_history = request.conversationHistory
    
    detection_result = scam_detector.detect(message_text)
    
    if detection_result["is_scam"]:
        try:
            llm_result = await llm_service.detect_scam_intent(
                message_text,
                conversation_history
            )
            detection_result["llm_analysis"] = llm_result
        except Exception:
            pass
    
    intelligence = intelligence_extractor.extract_from_text(message_text)
    
    return {
        "status": "success",
        "detection": detection_result,
        "intelligence": intelligence
    }


@app.post("/extract-intelligence")
async def extract_intelligence(request: IncomingMessage):
    session_id = request.sessionId
    conversation_history = request.conversationHistory
    message = request.message
    
    full_history = build_conversation_history(conversation_history, message)
    
    all_text = " ".join([msg.get("text", "") for msg in full_history])
    basic_intel = intelligence_extractor.extract_from_text(all_text)
    
    try:
        llm_intel = await llm_service.extract_intelligence_llm(full_history)
        merged_intel = intelligence_extractor.merge_intelligence(basic_intel, llm_intel)
        merged_intel["tactics"] = llm_intel.get("tactics", [])
        merged_intel["agentNotes"] = llm_intel.get("agentNotes", "")
    except Exception:
        merged_intel = basic_intel
        merged_intel["tactics"] = []
        merged_intel["agentNotes"] = ""
    
    return {
        "status": "success",
        "sessionId": session_id,
        "extractedIntelligence": merged_intel
    }


@app.post("/callback")
async def manual_callback(request: IncomingMessage):
    session_id = request.sessionId
    session_data = session_manager.get_session(session_id)
    
    if not session_data:
        conversation_history = request.conversationHistory
        message = request.message
        full_history = build_conversation_history(conversation_history, message)
        
        all_text = " ".join([msg.get("text", "") for msg in full_history])
        intel = intelligence_extractor.extract_from_text(all_text)
        
        session_data = {
            "scam_detected": True,
            "turn_count": len(full_history),
            "extracted_intelligence": intel,
            "agent_notes": "Manual callback triggered"
        }
    
    success = await send_callback_to_guvi(session_id, session_data)
    
    return {
        "status": "success" if success else "failed",
        "callbackSent": success,
        "payload": {
            "sessionId": session_id,
            "scamDetected": session_data.get("scam_detected", True),
            "totalMessagesExchanged": session_data.get("turn_count", 0),
            "extractedIntelligence": session_data.get("extracted_intelligence", {}),
            "agentNotes": session_data.get("agent_notes", "")
        }
    }


@app.get("/session/{session_id}")
async def get_session_info(session_id: str):
    session_data = session_manager.get_session(session_id)
    
    if not session_data:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return {
        "status": "success",
        "sessionId": session_id,
        "scamDetected": session_data.get("scam_detected", False),
        "scamType": session_data.get("scam_type"),
        "confidence": session_data.get("confidence", 0),
        "turnCount": session_data.get("turn_count", 0),
        "extractedIntelligence": session_data.get("extracted_intelligence", {}),
        "callbackSent": session_data.get("callback_sent", False)
    }


@app.delete("/session/{session_id}")
async def end_session(session_id: str):
    session_data = session_manager.get_session(session_id)
    
    if not session_data:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if session_data.get("scam_detected") and not session_data.get("callback_sent"):
        await send_callback_to_guvi(session_id, session_data)
    
    session_manager.delete_session(session_id)
    
    return {
        "status": "success",
        "message": "Session ended"
    }


def get_fallback_response(scam_type: Optional[str], turn: int) -> str:
    responses = {
        "Banking Fraud": [
            "Oh no, what happened to my account?",
            "What do I need to do to fix this?",
            "Should I share my details with you?",
            "What information do you need from me?",
            "Is this really from the bank?"
        ],
        "UPI Fraud": [
            "My UPI is not working? What should I do?",
            "Do I need to verify something?",
            "What details do you need?",
            "Can you help me fix this?",
            "Should I send you my UPI ID?"
        ],
        "Phishing": [
            "Why do you need this information?",
            "Is this official?",
            "What will happen if I don't verify?",
            "Can you tell me more about the issue?",
            "What details should I provide?"
        ],
        "Lottery Scam": [
            "I won something? Really?",
            "How do I claim my prize?",
            "What do I need to pay?",
            "Is this real?",
            "How did I win?"
        ]
    }
    
    default_responses = [
        "Can you explain more?",
        "What should I do?",
        "I don't understand, please help",
        "What information do you need?",
        "How can I verify this?"
    ]
    
    response_list = responses.get(scam_type, default_responses)
    idx = turn % len(response_list)
    return response_list[idx]


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
