import logging
import json
from typing import Dict, Any, Optional

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

from config.settings import OPENAI_API_KEY

logger = logging.getLogger(__name__)

class AIExplainer:
    """
    Phase 6.3 - AI Explanation Engine
    
    Generates human-readable security guidance based on an aggregated set of indicators.
    Functions non-destructively, returning structured explanation dictionaries downstream.
    Only triggers on SUSPICIOUS or HIGH_RISK classifications to save API costs & latency.
    """
    
    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        if OPENAI_API_KEY and OpenAI:
            self.client = OpenAI(api_key=OPENAI_API_KEY, timeout=timeout)
        else:
            self.client = None
            if not OpenAI:
                logger.warning("OpenAI package not installed.")
            if not OPENAI_API_KEY:
                logger.warning("OPENAI_API_KEY missing from configuration.")
                
    def _create_fallback_response(self, reason: str = "unavailable") -> Dict[str, str]:
        """Returns standard fallback when AI generation fails."""
        return {
            "ai_summary": f"AI analysis {reason}.",
            "threat_explanation": "The AI service could not generate a threat explanation.",
            "recommended_action": "Exercise caution before executing this file.",
            "confidence": "unknown"
        }

    def _construct_prompt(self, payload: Dict[str, Any]) -> str:
        """Converts the structured payload into a tight string prompt."""
        static = payload.get("static_analysis", {})
        risk = payload.get("risk_assessment", {})
        ti = payload.get("threat_intelligence", {})
        
        prompt_parts = [
            "You are a cybersecurity analyst.",
            "A file has been analyzed by a malware detection system.\n",
            "Static analysis indicators:",
            f"Entropy: {static.get('entropy', 'N/A')}",
            f"Suspicious imports: {static.get('suspicious_imports', 'N/A')}",
            f"Packed executable: {str(static.get('packed_flag', 'N/A')).lower()}\n",
            "Risk evaluation:",
            f"Risk score: {risk.get('risk_score', 'N/A')}",
            f"Classification: {risk.get('classification', 'N/A')}\n"
        ]
        
        if ti.get("status") != "unknown":
            prompt_parts.extend([
                "Threat intelligence results:",
                f"VirusTotal detections: {ti.get('virus_total_detections', 0)} out of {ti.get('virus_total_total_engines', 0)} engines",
                f"MalwareBazaar match: {str(ti.get('malwarebazaar_match', False)).lower()}",
                f"Malware family: {ti.get('malware_family') or 'N/A'}\n"
            ])
            
        prompt_parts.extend([
            "Explain why this file may be malicious.",
            "Provide guidance for the user.",
            "Keep the explanation concise and professional.",
            "Output your response purely as JSON with the following exact keys:",
            '{"ai_summary": "...", "threat_explanation": "...", "recommended_action": "...", "confidence": "..."}'
        ])
        
        return "\n".join(prompt_parts)

    def generate_explanation(self, payload: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """
        Takes aggregated intelligence payload and returns a dictionary explanation mapping.
        Only executes if the file is flagged as SUSPICIOUS or HIGH_RISK.
        """
        # Trigger Condition: Only analyze actionable risks
        classification = payload.get("risk_assessment", {}).get("classification", "SAFE")
        if classification not in ["SUSPICIOUS", "HIGH_RISK"]:
            logger.info(f"Skipping AI Explanation for classification: {classification}")
            return None
            
        if not self.client:
            logger.error("AI Explainer cannot run. Client not initialized.")
            return self._create_fallback_response("unavailable (client not initialized)")
            
        prompt = self._construct_prompt(payload)
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo", # Cost effective choice for prompt constraint
                messages=[
                    {"role": "system", "content": "You are a specialized JSON-outputting security analyst AI."},
                    {"role": "user", "content": prompt}
                ],
                response_format={ "type": "json_object" }, 
                temperature=0.3,
                max_tokens=250
            )
            
            content = response.choices[0].message.content
            
            # Parse structure back safely
            if not content:
                raise ValueError("Empty response from AI")
                
            ai_data = json.loads(content)
            
            # Normalize structure ensuring all keys exist
            return {
                "ai_summary": ai_data.get("ai_summary", "Summary unavailable."),
                "threat_explanation": ai_data.get("threat_explanation", "Explanation unavailable."),
                "recommended_action": ai_data.get("recommended_action", "Exercise caution before executing this file."),
                "confidence": ai_data.get("confidence", "unknown")
            }
            
        except json.JSONDecodeError as str_e:
            logger.error(f"Failed to decode OpenAI JSON payload: {str_e}")
            return self._create_fallback_response("failed (invalid output structure)")
        except Exception as e:
            logger.error(f"OpenAI API generation failed: {e}")
            return self._create_fallback_response("failed (API error or timeout)")
