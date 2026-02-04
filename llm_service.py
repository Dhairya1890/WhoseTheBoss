import os
import re
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime
from google import genai
from google.genai import types
from dotenv import load_dotenv

load_dotenv()


GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = "gemini-2.5-flash-lite"

client = genai.Client(api_key=GEMINI_API_KEY)


class GeminiLLMService:

    def __init__(self):
        self.api_key = GEMINI_API_KEY
        self.model = GEMINI_MODEL
        self.client = client

    async def _call_gemini(self, prompt: str, system_instruction: str = None) -> str:
        try:
            config = types.GenerateContentConfig(
                temperature=0.7,
                max_output_tokens=150,  # Reduced to save tokens
                top_p=0.9,
            )
            
            if system_instruction:
                config.system_instruction = system_instruction
            
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=config
            )
            
            if response and response.text:
                return response.text
            return ""
        except Exception as e:
            error_str = str(e)
            if "429" in error_str or "RESOURCE_EXHAUSTED" in error_str:
                print(f"Rate limited, waiting 5s...")
                await asyncio.sleep(5)
                # Single retry
                try:
                    response = self.client.models.generate_content(
                        model=self.model,
                        contents=prompt,
                        config=config
                    )
                    if response and response.text:
                        return response.text
                except Exception:
                    pass
            print(f"Gemini API error: {e}")
            return ""

    async def detect_scam_intent(self, message: str, conversation_history: List[Dict] = None) -> Dict:
        history_text = ""
        if conversation_history:
            for msg in conversation_history[-3:]:  # Reduced from 5 to 3
                sender = msg.get("sender", "unknown")
                text = msg.get("text", "")
                history_text += f"{sender}: {text}\n"
        
        system_instruction = """Scam detection. Return JSON: is_scam(bool), confidence(0-1), scam_type, indicators[], reasoning"""

        prompt = f"""History:\n{history_text}\nMessage: {message}\nJSON:"""

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
            raise Exception("LLM failed to provide a valid scam detection response")

    async def generate_agent_response(
        self,
        scam_type: str,
        message: str,
        conversation_history: List[Dict],
        extracted_intelligence: Dict
    ) -> str:
        history_text = ""
        if conversation_history:
            # Only use last 3 messages to reduce tokens
            for msg in conversation_history[-3:]:
                sender = msg.get("sender", "unknown")
                text = msg.get("text", "")
                if sender == "scammer":
                    history_text += f"S: {text}\n"
                else:
                    history_text += f"V: {text}\n"
        
        system_instruction = """Play naive victim. Extract scammer info (accounts, UPI, phones, links). Sound confused, ask for details. 1-2 sentences only."""

        prompt = f"""Type:{scam_type}\nChat:\n{history_text}\nScammer:{message}\nReply as victim:"""

        response = await self._call_gemini(prompt, system_instruction)
        
        if response:
            response = response.strip().strip('"').strip("'")
            if len(response) > 200:
                response = response[:200]
            return response
        

    async def extract_intelligence_llm(self, conversation_history: List[Dict]) -> Dict:
        # Only use last 5 messages to reduce tokens
        recent_msgs = conversation_history[-5:] if len(conversation_history) > 5 else conversation_history
        full_conversation = ""
        for msg in recent_msgs:
            sender = msg.get("sender", "unknown")
            text = msg.get("text", "")
            full_conversation += f"{sender}: {text}\n"
        
        system_instruction = """Extract: bankAccounts[], upiIds[], phishingLinks[], phoneNumbers[], tactics[]. Return JSON only."""

        prompt = f"""Chat:\n{full_conversation}\nJSON:"""

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
            raise Exception("LLM failed to extract intelligence from conversation")


llm_service = GeminiLLMService()
