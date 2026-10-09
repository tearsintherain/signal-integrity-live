import os
from dotenv import load_dotenv
from google import genai

load_dotenv()

key = os.getenv("GEMINI_API_KEY")
if not key:
    raise SystemExit("ERROR: GEMINI_API_KEY not found in .env")

client = genai.Client(api_key=key)

print("Testing Gemini API...")

try:
    response = client.models.generate_content(
        model="gemini-flash-latest",
        contents=(
            "You are testing a cybersecurity application. "
            "Reply with exactly: SIGNAL INTEGRITY AI ONLINE"
        ),
    )
    print("SUCCESS:", response.text)

except Exception as exc:
    print(f"API TEST FAILED: {type(exc).__name__}: {exc}")
    raise SystemExit(1)
