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

# List of models to try in order (fallback chain)
GEMINI_MODELS = [
    "gemini-3-pro-preview",
    "gemini-3-flash-preview",
    "gemini-2.5-flash-lite",
    "gemini-2.0-flash",
    "gemini-2.5-flash",
    "gemini-2.0-flash-001"
]

client = genai.Client(api_key=GEMINI_API_KEY)


class GeminiLLMService:

    def __init__(self):
        self.api_key = GEMINI_API_KEY
        self.models = GEMINI_MODELS
        self.current_model_index = 0
        self.client = client
        self.model_exhausted = {}  # Track which models are rate limited

    @property
    def model(self):
        return self.models[self.current_model_index]

    def _switch_to_next_model(self) -> bool:
        """Switch to next available model. Returns False if all models exhausted."""
        self.model_exhausted[self.model] = datetime.now()
        
        # Try to find a non-exhausted model
        for i in range(len(self.models)):
            next_index = (self.current_model_index + 1 + i) % len(self.models)
            model_name = self.models[next_index]
            
            # Check if model was exhausted more than 60 seconds ago (reset it)
            if model_name in self.model_exhausted:
                time_diff = (datetime.now() - self.model_exhausted[model_name]).seconds
                if time_diff > 60:
                    del self.model_exhausted[model_name]
            
            if model_name not in self.model_exhausted:
                self.current_model_index = next_index
                print(f"Switched to model: {self.model}")
                return True
        
        print("All models exhausted, waiting...")
        return False

    async def _call_gemini(self, prompt: str, system_instruction: str = None, max_tokens: int = 1024) -> str:
        max_retries = len(self.models) + 1
        
        for attempt in range(max_retries):
            try:
                config = types.GenerateContentConfig(
                    temperature=0.7,
                    max_output_tokens=max_tokens,
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
                    print(f"Rate limited on {self.model}, switching model...")
                    if self._switch_to_next_model():
                        continue  # Retry with new model
                    else:
                        # All models exhausted, wait and retry
                        print("All models rate limited, waiting 10s...")
                        await asyncio.sleep(10)
                        # Reset exhausted models after waiting
                        self.model_exhausted.clear()
                        continue
                print(f"Gemini API error: {e}")
                return ""
        
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

        response = await self._call_gemini(prompt, system_instruction, max_tokens=200)
        
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
        
        system_instruction = """You are a JSON extractor. Extract scam data and return ONLY a single-line compact JSON. Format: {"bankAccounts":[],"upiIds":[],"phishingLinks":[],"phoneNumbers":[],"agentNotes":"brief scam summary"}"""

        prompt = f"""Extract scam intelligence from chat. Include agentNotes summarizing scammer tactics. Return ONLY compact JSON:
{full_conversation}
JSON:"""

        response = await self._call_gemini(prompt, system_instruction, max_tokens=512)
        
        return self._parse_intelligence_response(response, conversation_history)

    def _parse_intelligence_response(self, response: str, conversation_history: List[Dict]) -> Dict:
        import json
        
        # Return empty structure if response is empty
        empty_result = {
            "bankAccounts": [],
            "upiIds": [],
            "phishingLinks": [],
            "phoneNumbers": [],
            "suspiciousKeywords": [],
            "tactics": [],
            "agentNotes": ""
        }
        
        if not response or not response.strip():
            print("Warning: LLM returned empty response for intelligence extraction")
            return empty_result
        
        try:
            response = response.strip()
            if response.startswith("```json"):
                response = response[7:]
            if response.startswith("```"):
                response = response[3:]
            if response.endswith("```"):
                response = response[:-3]
            response = response.strip()
            
            # Try to repair truncated JSON
            response = self._repair_json(response)
            
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
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            print(f"Warning: Failed to parse LLM response: {e}. Response was: {response[:100]}")
            # Try to extract partial data from truncated JSON using regex
            return self._extract_partial_intelligence(response, empty_result)

    def _repair_json(self, json_str: str) -> str:
        """Attempt to repair truncated or malformed JSON"""
        json_str = json_str.strip()
        
        # If it doesn't start with {, find the first {
        if not json_str.startswith('{'):
            idx = json_str.find('{')
            if idx != -1:
                json_str = json_str[idx:]
        
        # Count brackets to check if JSON is complete
        open_braces = json_str.count('{')
        close_braces = json_str.count('}')
        open_brackets = json_str.count('[')
        close_brackets = json_str.count(']')
        
        # If balanced, return as-is
        if open_braces == close_braces and open_brackets == close_brackets:
            return json_str
        
        # Try to close truncated arrays and objects
        # Remove trailing incomplete values
        # Pattern: ends with "key": or "key":[ or incomplete string
        import re
        
        # Remove incomplete trailing content
        json_str = re.sub(r',\s*"[^"]*"?\s*:?\s*\[?\s*"?[^"\]]*$', '', json_str)
        
        # Add missing closing brackets
        while open_brackets > close_brackets:
            json_str += ']'
            close_brackets += 1
        
        # Add missing closing braces
        while open_braces > close_braces:
            json_str += '}'
            close_braces += 1
        
        return json_str

    def _extract_partial_intelligence(self, response: str, empty_result: Dict) -> Dict:
        """Extract whatever data we can from a truncated/malformed JSON response"""
        import re
        
        result = empty_result.copy()
        
        # Extract bank accounts - look for numbers 9-18 digits (with or without closing quote)
        bank_matches = re.findall(r'"(\d{9,18})"?', response)
        if bank_matches:
            result["bankAccounts"] = list(set(bank_matches))[:10]
        
        # Extract UPI IDs (with or without closing quote)
        upi_matches = re.findall(r'"([\w\.\-]+@[a-zA-Z]+)"?', response)
        if upi_matches:
            result["upiIds"] = list(set(upi_matches))[:10]
        
        # Extract phone numbers (with or without closing quote)
        phone_matches = re.findall(r'"(\+?91?\d{10})"?', response)
        if phone_matches:
            result["phoneNumbers"] = list(set(phone_matches))[:10]
        
        # Extract URLs (with or without closing quote)
        url_matches = re.findall(r'"(https?://[^\s"\]]+)"?', response)
        if url_matches:
            result["phishingLinks"] = list(set(url_matches))[:10]
        
        # Extract keywords (simple strings in arrays)
        keyword_matches = re.findall(r'"([a-zA-Z][a-zA-Z\s]{2,20})"', response)
        if keyword_matches:
            # Filter out field names
            field_names = {"bankAccounts", "upiIds", "phishingLinks", "phoneNumbers", "suspiciousKeywords", "tactics", "agentNotes"}
            keywords = [k for k in keyword_matches if k not in field_names]
            result["suspiciousKeywords"] = list(set(keywords))[:15]
        
        print(f"Extracted partial data from truncated response: {result}")
        return result


llm_service = GeminiLLMService()