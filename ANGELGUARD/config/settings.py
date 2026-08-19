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

# Step 7 reliability hardening: analysis/static_analyzer.py reads the whole
# file into memory and its entropy/string extraction scale with file size
# (measured ~0.42s/MB, memory delta ~1:1 with file size — see DECISIONS.md
# Step 7). Files above this size skip full analysis with a controlled,
# honest "unanalyzed — exercise caution" result rather than blocking the
# single watchdog dispatch thread for minutes. Override via env var for
# tuning without a code change.
MAX_ANALYSIS_FILE_SIZE_BYTES = int(os.getenv("MAX_ANALYSIS_FILE_SIZE_BYTES", 50 * 1024 * 1024))
