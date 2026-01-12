# ANGELGUARD

**ANGELGUARD** is an AI-Driven Human-Centric Endpoint Security Guardian.

## Overview
ANGELGUARD monitors user actions related to file downloads and execution, analyzes files BEFORE execution using deep static analysis and ML, and warns the user via a floating desktop UI.

## Features
- **File Monitoring**: Detects new downloads and execution attempts.
- **Static Analysis**: PE header analysis, string extraction, entropy calculation.
- **AI Risk Scoring**: ML-based classification (Safe/Suspicious).
- **Angel UI**: Non-intrusive desktop guardian.
- **Logging**: Local SQLite database for event tracking.

## Usage
1. Install dependencies: `pip install -r requirements.txt`
2. Run the guardian: `python src/main.py`

## Constraints
- No kernel drivers.
- No dynamic sandboxing.
- No network sniffing.
