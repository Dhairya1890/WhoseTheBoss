from google import genai
from dotenv import load_dotenv
import os

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

client = genai.Client()

response = client.models.generate_content(
    model="gemini-2.5-flash-lite",
    contents="You are a stranger at a cafe, respond to a stranger having the following question : Hello can I sit with you and have a coffee?",
)

print(response.text)