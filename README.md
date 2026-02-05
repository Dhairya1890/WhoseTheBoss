# 🛡️ Scam Detection & Engagement API

An intelligent anti-scam chatbot API that detects, engages, and extracts intelligence from scammers using AI-powered analysis. Built with FastAPI and Google Gemini.

## 🎯 Features

- **Real-time Scam Detection** - Pattern-based and LLM-powered scam identification
- **Intelligent Engagement** - AI generates convincing victim responses to extract information
- **Intelligence Extraction** - Automatically extracts bank accounts, UPI IDs, phone numbers, and phishing links
- **Session Management** - Tracks conversation state and scam progression
- **Automatic Callbacks** - Sends extracted intelligence to GUVI endpoint when sufficient data is collected
- **Multi-Model Fallback** - Automatic failover between Gemini models for reliability

## 🏗️ Architecture

```
Chat/
├── main.py           # FastAPI application & endpoints
├── llm_service.py    # Gemini LLM integration
├── models.py         # Pydantic data models
├── auth.py           # API key authentication
└── requirements.txt  # Python dependencies
```

### Core Components

| Component | Description |
|-----------|-------------|
| `SessionManager` | Manages conversation sessions and state |
| `IntelligenceExtractor` | Regex-based extraction of sensitive data |
| `ScamDetector` | Rule-based scam detection with confidence scoring |
| `GeminiLLMService` | AI-powered analysis and response generation |

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- Google Gemini API Key

### Installation

```bash
# Clone the repository
cd Chat

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
```

### Configuration

Create a `.env` file in the project root:

```env
GEMINI_API_KEY=your_gemini_api_key_here
API_KEY=your-secret-api-key-12345
PORT=8000
```

### Running the Server

```bash
# Development mode with hot reload
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Or run directly
python main.py
```

## 📡 API Endpoints

### `POST /` - Process Message

Main endpoint for processing incoming scam messages and generating responses.

**Request:**
```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "Your account is blocked! Share OTP to verify.",
    "timestamp": "2026-02-05T10:00:00Z"
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "en"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "Oh no! Which account is blocked? I have multiple accounts..."
}
```

---

### `POST /analyze` - Analyze Message

Analyzes a message for scam indicators without generating a response.

**Response:**
```json
{
  "status": "success",
  "detection": {
    "is_scam": true,
    "confidence": 0.85,
    "scam_type": "Banking Fraud",
    "indicators": ["Critical: 'share otp'", "Warning: 'blocked'"]
  },
  "intelligence": {
    "phoneNumbers": [],
    "upiIds": [],
    "bankAccounts": [],
    "phishingLinks": []
  }
}
```

---

### `POST /extract-intelligence` - Extract Intelligence

Extracts all intelligence from conversation history using both regex and LLM.

---

### `POST /callback` - Manual Callback

Manually triggers the callback to GUVI endpoint with collected intelligence.

---

### `GET /session/{session_id}` - Get Session Info

Retrieves current session state and extracted intelligence.

---

### `DELETE /session/{session_id}` - End Session

Ends a session and sends final callback if scam was detected.

## 🔍 Scam Detection

### Detection Methods

1. **Critical Keywords** (High confidence: 0.8)
   - "account blocked", "verify immediately", "share otp/cvv/pin"

2. **Warning Keywords** (Medium confidence: 0.15 each)
   - "verify", "urgent", "suspended", "blocked", "payment failed"

3. **Pattern Analysis**
   - Suspicious URLs (bit.ly, tinyurl, etc.)
   - UPI ID patterns
   - Phone number patterns

4. **LLM Analysis**
   - Deep contextual analysis using Gemini models

### Scam Types Detected

- Banking Fraud
- Phishing
- UPI Fraud
- Lottery/Prize Scams
- Generic Fraud

## 🤖 LLM Integration

### Supported Models (Fallback Order)

1. `gemini-3-pro-preview`
2. `gemini-3-flash-preview`
3. `gemini-2.5-flash-lite`
4. `gemini-2.0-flash`
5. `gemini-2.5-flash`
6. `gemini-2.0-flash-001`

The service automatically switches models on rate limiting (429 errors) with a 60-second cooldown period.

## 📊 Intelligence Extraction

Automatically extracts:

| Type | Example |
|------|---------|
| Phone Numbers | `+91 9876543210`, `9876543210` |
| UPI IDs | `user@paytm`, `name@ybl` |
| Bank Accounts | 9-18 digit numbers |
| Phishing Links | `http://bit.ly/xyz` |
| Suspicious Keywords | "urgent", "otp", "verify" |

## 🔄 Callback System

Automatically sends intelligence to GUVI when:
- Scam is detected
- At least 3 conversation turns completed
- Either 10+ turns OR 3+ intelligence items extracted

**Callback Payload:**
```json
{
  "sessionId": "string",
  "scamDetected": true,
  "totalMessagesExchanged": 10,
  "extractedIntelligence": {
    "bankAccounts": [],
    "upiIds": [],
    "phishingLinks": [],
    "phoneNumbers": [],
    "suspiciousKeywords": []
  },
  "agentNotes": "Scammer behavior: used urgency tactics..."
}
```

## 🛠️ Development

### Project Structure

```
main.py
├── SessionManager          # Session state management
├── IntelligenceExtractor   # Regex-based extraction
├── ScamDetector            # Rule-based detection
├── process_message()       # Main endpoint handler
├── analyze_message()       # Analysis endpoint
├── extract_intelligence()  # Intelligence endpoint
└── send_callback_to_guvi() # Callback handler
```

### Adding New Scam Patterns

Edit the `ScamDetector` class in `main.py`:

```python
self.critical_keywords = {
    "new critical phrase",
    # ... existing keywords
}
```

## 📝 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GEMINI_API_KEY` | Google Gemini API key | Required |
| `API_KEY` | API authentication key | `your-secret-api-key-12345` |
| `PORT` | Server port | `8000` |

## 📦 Dependencies

- **FastAPI** - Web framework
- **google-genai** - Gemini AI integration
- **Pydantic** - Data validation
- **httpx** - Async HTTP client
- **python-dotenv** - Environment management
- **uvicorn** - ASGI server

## 📄 License

This project is part of the GUVI Hackathon.

---

Built with ❤️ for fighting scams
