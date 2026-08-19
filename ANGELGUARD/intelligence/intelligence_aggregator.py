from typing import Dict, Any
import datetime

class IntelligenceAggregator:
    """
    Phase 6.2 - Intelligence Aggregation Layer
    
    Responsible for merging local static analysis indicators, deterministic risk evaluation scores, 
    and global threat intelligence reputation into a single, unified JSON-compatible structure.
    
    This unified payload is then consumed by the downstream AI explanation engine and alerting systems.
    """
    
    @staticmethod
    def aggregate_intelligence(analysis_result: Dict[str, Any], 
                               risk_result: Dict[str, Any], 
                               threat_intel_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merges three discrete intelligence sources into a single payload.
        Handles missing keys gracefully — and, critically, does NOT invent
        false values (e.g. entropy=0.0, packed_flag=False) for indicators
        analysis_result genuinely doesn't contain. Where a value is
        unavailable, the corresponding key is simply omitted from
        "static_analysis" rather than populated with a misleading default;
        downstream consumers (ai/ai_explainer.py) already read these via
        `.get(key, 'N/A')` and treat an absent key as "not available".

        Args:
            analysis_result: Dictionary from static_analyzer.analyze_file()
                (canonical shape: file_path, file_size, hash,
                num_suspicious_imports, high_entropy_sections, sections
                (list of {"name","entropy","size"}), error).
            risk_result: Dictionary from
                decision.risk_evaluator.evaluate_risk_as_dict()
                ({"risk_score", "classification", "reasons"}).
            threat_intel_result: Dictionary from
                ThreatIntelClient.get_reputation().

        Returns:
            Dict: The aggregated unified intelligence payload.
        """
        # 1. Base details
        payload = {
            "file_path": analysis_result.get("file_path", "unknown"),
            "hash": analysis_result.get("hash") or threat_intel_result.get("hash", "unknown"),
        }

        # 2. Static Analysis Sub-section
        # Extract features avoiding cluttering the payload with base properties again
        static_analysis = {
            "suspicious_imports": analysis_result.get("num_suspicious_imports", 0),
        }

        # file_size / high_entropy_sections are always present in a real
        # analyze_file() result (defaulted to 0 even on total failure), so
        # a plain "in" check is safe and mirrors how risk_evaluator.py
        # itself already treats these two fields as always-meaningful.
        if "file_size" in analysis_result:
            static_analysis["file_size"] = analysis_result["file_size"]
        if "high_entropy_sections" in analysis_result:
            static_analysis["high_entropy_sections"] = analysis_result["high_entropy_sections"]
            static_analysis["packed_flag"] = analysis_result["high_entropy_sections"] > 0

        # entropy has no single-value equivalent in static_analyzer's own
        # output — only a list of per-section entropies. Report the
        # maximum (a single small high-entropy stub matters more than a
        # low average across many sections). If there is no section data
        # at all (e.g. the PE failed to parse), there is genuinely no
        # entropy to report — omit the key rather than claim 0.0.
        sections = analysis_result.get("sections")
        if sections:
            static_analysis["entropy"] = max(s.get("entropy", 0.0) for s in sections)

        payload["static_analysis"] = static_analysis
        
        # 3. Risk Assessment Sub-section
        payload["risk_assessment"] = {
            "risk_score": risk_result.get("risk_score", 0),
            "classification": risk_result.get("classification", "UNKNOWN"),
            "reasons": risk_result.get("reasons", [])
        }
        
        # 4. Threat Intelligence Sub-section
        # Handle the fallback state gracefully
        if threat_intel_result.get("status") == "unknown":
            payload["threat_intelligence"] = {
                "status": "unknown"
            }
        else:
            payload["threat_intelligence"] = {
                "virus_total_detections": threat_intel_result.get("virus_total_detections", 0),
                "virus_total_total_engines": threat_intel_result.get("virus_total_total_engines", 0),
                "malwarebazaar_match": threat_intel_result.get("malwarebazaar_match", False),
                "malware_family": threat_intel_result.get("malware_family")
            }
            
            # Optionally include confidence if the client provided it
            if "confidence" in threat_intel_result:
                payload["threat_intelligence"]["confidence"] = threat_intel_result["confidence"]
        
        # 5. Attach UTC ISO timestamp representing aggregation time
        # Append 'Z' to formally denote UTC
        payload["timestamp"] = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        
        return payload

# Provide a functional wrapper aligned with prompt signature for convenience
def aggregate_intelligence(analysis_result: Dict[str, Any], 
                           risk_result: Dict[str, Any], 
                           threat_intel_result: Dict[str, Any]) -> Dict[str, Any]:
    return IntelligenceAggregator.aggregate_intelligence(analysis_result, risk_result, threat_intel_result)
