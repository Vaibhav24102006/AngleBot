import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# MalwareBazaar API Configuration (Key is optional, but increases rate limits)
MB_API_KEY = os.getenv("MB_API_KEY", "")
MB_API_URL = "https://mb-api.abuse.ch/api/v1/"

# VirusTotal API Configuration
VT_API_KEY = os.getenv("VT_API_KEY", "")
VT_API_URL = "https://www.virustotal.com/api/v3/files/"

# OpenAI API Configuration (Phase 6.3)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
