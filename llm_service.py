import os
import re
import httpx
from typing import Dict, List, Optional, Any
from datetime import datetime

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = "gemini-2.0-flash"
GEMINI_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"


class GeminiLLMService:

    def __init__(self):
        self.api_key = GEMINI_API_KEY
        self.model = GEMINI_MODEL
        self.url = GEMINI_URL

    async def _call_gemini(self, prompt: str, system_instruction: str = None) -> str:
        headers = {
            "Content-Type": "application/json"
        }
        
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.7,
                "maxOutputTokens": 256,
                "topP": 0.9
            }
        }
        
        if system_instruction:
            payload["systemInstruction"] = {
                "parts": [{"text": system_instruction}]
            }
        
        url_with_key = f"{self.url}?key={self.api_key}"
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(url_with_key, json=payload, headers=headers)
            
            if response.status_code == 200:
                result = response.json()
                if "candidates" in result and len(result["candidates"]) > 0:
                    candidate = result["candidates"][0]
                    if "content" in candidate and "parts" in candidate["content"]:
                        return candidate["content"]["parts"][0].get("text", "")
            return ""

    async def detect_scam_intent(self, message: str, conversation_history: List[Dict] = None) -> Dict:
        history_text = ""
        if conversation_history:
            for msg in conversation_history[-5:]:
                sender = msg.get("sender", "unknown")
                text = msg.get("text", "")
                history_text += f"{sender}: {text}\n"
        
        system_instruction = """You are a scam detection expert. Analyze messages for scam indicators.
Return ONLY a JSON object with these fields:
- is_scam: boolean
- confidence: float between 0 and 1
- scam_type: string (Banking Fraud, UPI Fraud, Phishing, Lottery Scam, Tech Support Scam, or null)
- indicators: list of detected scam indicators
- reasoning: brief explanation"""

        prompt = f"""Analyze this message for scam intent:

Conversation History:
{history_text}

Current Message: {message}

Respond with JSON only."""

        response = await self._call_gemini(prompt, system_instruction)
        
        return self._parse_detection_response(response, message)

    def _parse_detection_response(self, response: str, original_message: str) -> Dict:
        import json
        
        try:
            response = response.strip()
            if response.startswith("```json"):
                response = response[7:]
            if response.startswith("```"):
                response = response[3:]
            if response.endswith("```"):
                response = response[:-3]
            response = response.strip()
            
            result = json.loads(response)
            return {
                "is_scam": result.get("is_scam", False),
                "confidence": float(result.get("confidence", 0.0)),
                "scam_type": result.get("scam_type"),
                "indicators": result.get("indicators", []),
                "reasoning": result.get("reasoning", ""),
                "detection_method": "llm"
            }
        except (json.JSONDecodeError, KeyError, TypeError):
            return self._fallback_detection(original_message)

    def _fallback_detection(self, message: str) -> Dict:
        text_lower = message.lower()
        
        critical_keywords = [
            "account blocked", "verify immediately", "share otp",
            "share cvv", "share pin", "account suspended",
            "urgent verification", "confirm password"
        ]
        
        warning_keywords = [
            "verify", "urgent", "immediately", "account", "bank",
            "suspended", "blocked", "upi", "payment failed"
        ]
        
        confidence = 0.0
        indicators = []
        scam_type = None
        
        for keyword in critical_keywords:
            if keyword in text_lower:
                confidence += 0.4
                indicators.append(f"Critical keyword: {keyword}")
                scam_type = "Banking Fraud"
        
        warning_count = 0
        for keyword in warning_keywords:
            if keyword in text_lower:
                confidence += 0.1
                warning_count += 1
                if warning_count <= 3:
                    indicators.append(f"Warning keyword: {keyword}")
        
        if warning_count >= 2 and not scam_type:
            scam_type = "Phishing"
        
        phone_pattern = re.compile(r'\+?\d{10,12}')
        if phone_pattern.search(message):
            confidence += 0.1
            indicators.append("Contains phone number")
        
        url_pattern = re.compile(r'http[s]?://[^\s]+|bit\.ly|tinyurl')
        if url_pattern.search(message):
            confidence += 0.15
            indicators.append("Contains suspicious URL")
        
        confidence = min(confidence, 1.0)
        is_scam = confidence >= 0.3
        
        return {
            "is_scam": is_scam,
            "confidence": round(confidence, 2),
            "scam_type": scam_type if is_scam else None,
            "indicators": indicators[:5],
            "reasoning": f"Fallback detection with {len(indicators)} indicators",
            "detection_method": "fallback"
        }

    async def generate_agent_response(
        self,
        scam_type: str,
        message: str,
        conversation_history: List[Dict],
        extracted_intelligence: Dict
    ) -> str:
        history_text = ""
        if conversation_history:
            for msg in conversation_history[-6:]:
                sender = msg.get("sender", "unknown")
                text = msg.get("text", "")
                if sender == "scammer":
                    history_text += f"Scammer: {text}\n"
                else:
                    history_text += f"You (victim): {text}\n"
        
        intel_summary = []
        if extracted_intelligence.get("phoneNumbers"):
            intel_summary.append(f"Phone numbers collected: {len(extracted_intelligence['phoneNumbers'])}")
        if extracted_intelligence.get("upiIds"):
            intel_summary.append(f"UPI IDs collected: {len(extracted_intelligence['upiIds'])}")
        if extracted_intelligence.get("phishingLinks"):
            intel_summary.append(f"Links collected: {len(extracted_intelligence['phishingLinks'])}")
        
        system_instruction = """You are playing a naive victim to extract information from a scammer.
Your goals:
1. Sound like a real confused person
2. Ask clarifying questions to extract more information
3. NEVER reveal you know it's a scam
4. Try to get: account numbers, UPI IDs, phone numbers, links, names
5. Show concern and willingness to comply, but ask for details
6. Keep responses short (1-2 sentences max)
7. Use simple language like a regular person would

Respond with ONLY the victim's reply text, nothing else."""

        prompt = f"""Scam Type: {scam_type}

Conversation so far:
{history_text}

Latest scammer message: {message}

Intelligence gathered so far: {', '.join(intel_summary) if intel_summary else 'None yet'}

Generate a response as the naive victim to continue extracting information."""

        response = await self._call_gemini(prompt, system_instruction)
        
        if response:
            response = response.strip().strip('"').strip("'")
            if len(response) > 200:
                response = response[:200]
            return response
        
        return self._get_fallback_response(scam_type, len(conversation_history))

    def _get_fallback_response(self, scam_type: str, turn: int) -> str:
        responses = {
            "Banking Fraud": [
                "Oh no, what happened to my account?",
                "What do I need to do to fix this?",
                "Should I share my account details with you?",
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
            ],
            "Tech Support Scam": [
                "My computer has a virus?",
                "What should I do?",
                "How can you help me?",
                "Is this serious?",
                "What information do you need?"
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

    async def extract_intelligence_llm(self, conversation_history: List[Dict]) -> Dict:
        full_conversation = ""
        for msg in conversation_history:
            sender = msg.get("sender", "unknown")
            text = msg.get("text", "")
            full_conversation += f"{sender}: {text}\n"
        
        system_instruction = """Extract intelligence from this scam conversation.
Return ONLY a JSON object with:
- bankAccounts: list of bank account numbers found
- upiIds: list of UPI IDs found (format: xxx@upi)
- phishingLinks: list of suspicious URLs found
- phoneNumbers: list of phone numbers found
- suspiciousKeywords: list of scam-related keywords used
- tactics: list of manipulation tactics identified (urgency, authority, fear, etc.)
- agentNotes: brief summary of scammer's approach"""

        prompt = f"""Conversation:
{full_conversation}

Extract all intelligence. Return JSON only."""

        response = await self._call_gemini(prompt, system_instruction)
        
        return self._parse_intelligence_response(response, conversation_history)

    def _parse_intelligence_response(self, response: str, conversation_history: List[Dict]) -> Dict:
        import json
        
        try:
            response = response.strip()
            if response.startswith("```json"):
                response = response[7:]
            if response.startswith("```"):
                response = response[3:]
            if response.endswith("```"):
                response = response[:-3]
            response = response.strip()
            
            result = json.loads(response)
            return {
                "bankAccounts": result.get("bankAccounts", []),
                "upiIds": result.get("upiIds", []),
                "phishingLinks": result.get("phishingLinks", []),
                "phoneNumbers": result.get("phoneNumbers", []),
                "suspiciousKeywords": result.get("suspiciousKeywords", []),
                "tactics": result.get("tactics", []),
                "agentNotes": result.get("agentNotes", "")
            }
        except (json.JSONDecodeError, KeyError, TypeError):
            return self._fallback_intelligence_extraction(conversation_history)

    def _fallback_intelligence_extraction(self, conversation_history: List[Dict]) -> Dict:
        full_text = " ".join([msg.get("text", "") for msg in conversation_history])
        
        phone_pattern = re.compile(r'\+?91?\s*\d{10}|\b\d{10}\b')
        url_pattern = re.compile(r'http[s]?://[^\s]+')
        upi_pattern = re.compile(r'[\w\.\-]+@[a-zA-Z]+')
        bank_pattern = re.compile(r'\b\d{9,18}\b')
        
        keywords = []
        text_lower = full_text.lower()
        scam_keywords = [
            "urgent", "immediately", "blocked", "suspended", "verify",
            "otp", "cvv", "pin", "account", "bank", "upi", "payment",
            "prize", "won", "lottery", "claim", "refund"
        ]
        for kw in scam_keywords:
            if kw in text_lower:
                keywords.append(kw)
        
        tactics = []
        if any(w in text_lower for w in ["urgent", "immediately", "now", "today"]):
            tactics.append("Urgency")
        if any(w in text_lower for w in ["bank", "officer", "government", "rbi"]):
            tactics.append("Authority impersonation")
        if any(w in text_lower for w in ["blocked", "suspended", "terminated", "legal"]):
            tactics.append("Fear tactics")
        if any(w in text_lower for w in ["otp", "cvv", "pin", "password"]):
            tactics.append("Credential harvesting")
        
        return {
            "bankAccounts": list(set(bank_pattern.findall(full_text)))[:5],
            "upiIds": list(set(upi_pattern.findall(full_text)))[:5],
            "phishingLinks": list(set(url_pattern.findall(full_text)))[:5],
            "phoneNumbers": list(set(phone_pattern.findall(full_text)))[:5],
            "suspiciousKeywords": list(set(keywords))[:10],
            "tactics": tactics,
            "agentNotes": f"Detected {len(tactics)} manipulation tactics"
        }


llm_service = GeminiLLMService()
