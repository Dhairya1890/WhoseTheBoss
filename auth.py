from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader
from typing import Optional
import os
from dotenv import load_dotenv

load_dotenv()

# Load API key from environment variable
API_KEY = os.getenv("API_KEY", "your-secret-api-key-12345")  # Default for development
API_KEY_NAME = "X-API-Key"

api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

async def get_api_key(api_key: str = Security(api_key_header)) -> str:
    """Validate API key from header"""
    if api_key == API_KEY:
        return api_key
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API Key"
    )