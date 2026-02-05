from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from models import (
    IncomingMessage,
    ExtractedIntelligence,
    CallbackPayload,
    Message
)
from llm_service import llm_service
from typing import Dict, List, Optional
from datetime import datetime
import httpx
import re
import os

app = FastAPI()

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"]
# )

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
        # UPI pattern: handles formats like user@ybl, 9876543210@paytm, name.surname@okicici, etc.
        self.upi_pattern = re.compile(r'[a-zA-Z0-9\.\-_]+@[a-zA-Z][a-zA-Z0-9]*')
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
            "upiIds": upis[:15],
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
            indicators.append("Suspicious URL found")
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
        
        confidence = min(confidence, 1.0) # 1.0 represents 100%
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


def _generate_agent_notes(session_data: Dict) -> str:
    """Auto-generate agent notes summarizing scammer behavior and extracted intelligence"""
    scam_type = session_data.get("scam_type", "Unknown")
    confidence = session_data.get("confidence", 0)
    intel = session_data.get("extracted_intelligence", {})
    keywords = intel.get("suspiciousKeywords", [])
    
    notes_parts = []
    behavior_parts = []
    
    # Analyze scammer behavior based on keywords
    keyword_set = set(k.lower() for k in keywords)
    
    # Urgency tactics
    urgency_words = {"urgent", "immediately", "now", "fast", "quick", "hurry", "deadline"}
    if keyword_set & urgency_words:
        behavior_parts.append("used urgency tactics to pressure victim")
    
    # Fear tactics
    fear_words = {"blocked", "suspended", "terminated", "deactivated", "frozen", "locked", "cancelled"}
    if keyword_set & fear_words:
        behavior_parts.append("created fear about account/service termination")
    
    # Authority impersonation
    authority_words = {"bank", "rbi", "police", "government", "official", "manager", "officer"}
    if keyword_set & authority_words:
        behavior_parts.append("impersonated authority figure")
    
    # Payment redirection
    payment_words = {"upi", "payment", "transfer", "send", "pay", "amount", "refund"}
    if keyword_set & payment_words:
        behavior_parts.append("attempted payment redirection")
    
    # Credential harvesting
    cred_words = {"otp", "pin", "cvv", "password", "verify", "confirm", "details"}
    if keyword_set & cred_words:
        behavior_parts.append("attempted to extract sensitive credentials")
    
    # Prize/lottery scam
    prize_words = {"prize", "won", "winner", "lottery", "reward", "congratulations", "lucky"}
    if keyword_set & prize_words:
        behavior_parts.append("used fake prize/lottery lure")
    
    # Build behavior summary
    if behavior_parts:
        notes_parts.append(f"Scammer behavior: {', '.join(behavior_parts)}")
    
    # Add scam classification
    if scam_type and scam_type != "Unknown":
        notes_parts.append(f"Classification: {scam_type} ({int(confidence*100)}% confidence)")
    
    # Add extracted intelligence summary
    intel_summary = []
    if intel.get("bankAccounts"):
        intel_summary.append(f"{len(intel['bankAccounts'])} bank account(s)")
    if intel.get("upiIds"):
        intel_summary.append(f"{len(intel['upiIds'])} UPI ID(s)")
    if intel.get("phoneNumbers"):
        intel_summary.append(f"{len(intel['phoneNumbers'])} phone number(s)")
    if intel.get("phishingLinks"):
        intel_summary.append(f"{len(intel['phishingLinks'])} phishing link(s)")
    
    if intel_summary:
        notes_parts.append(f"Intelligence extracted: {', '.join(intel_summary)}")
    
    if not notes_parts:
        return "Scam engagement in progress - analyzing scammer behavior"
    
    return ". ".join(notes_parts)


def build_conversation_history(
    incoming_history: List[Message],
    current_message: Message
) -> List[Dict]:
    history = []
    
    for msg in incoming_history:
        # Handle both dict and Message object
        if isinstance(msg, dict):
            history.append({
                "sender": msg["sender"],
                "text": msg["text"],
                "timestamp": msg.get("timestamp") or 0
            })
        else:
            history.append({
                "sender": msg.sender,
                "text": msg.text,
                "timestamp": msg.timestamp or 0
            })
    
    history.append({
        "sender": current_message.sender,
        "text": current_message.text,
        "timestamp": current_message.timestamp or 0
    })
    
    return history


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "scam-detection-api"}


@app.head("/health")
async def health_head():
    """HEAD endpoint for lightweight monitoring/uptime checks"""
    return None


@app.post("/")
async def process_message(request: IncomingMessage):
    session_id = request.sessionId
    message = request.message
    conversation_history = request.conversationHistory
    
    session_data = session_manager.get_or_create(session_id)
    
    message_text = message.text
    
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
    
    # Only call LLM for intelligence extraction every 5 turns to save API quota
    turn_count = session_data.get("turn_count", 0)
    if turn_count % 5 == 0 and turn_count > 0:
        try:
            llm_intel = await llm_service.extract_intelligence_llm(full_history)
            session_data["extracted_intelligence"] = intelligence_extractor.merge_intelligence(
                session_data["extracted_intelligence"],
                llm_intel
            )
            if llm_intel.get("agentNotes"):
                session_data["agent_notes"] = llm_intel["agentNotes"]
        except Exception as e:
            print(f"Error extracting intelligence: {e}")
    
    # Auto-generate agent notes if empty
    if not session_data.get("agent_notes"):
        session_data["agent_notes"] = _generate_agent_notes(session_data)
    
    try:
        agent_reply = await llm_service.generate_agent_response(
            scam_type=session_data.get("scam_type", "Phishing"),
            message=message_text,
            conversation_history=full_history,
            extracted_intelligence=session_data["extracted_intelligence"]
        )
    except Exception as e:
        print(f"Error generating agent response: {e}")
    
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
    message_text = request.message.text
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
    
    all_text = " ".join([msg["text"] for msg in full_history])
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
        
        all_text = " ".join([msg["text"] for msg in full_history])
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


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
