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
        Handles missing keys gracefully.
        
        Args:
            analysis_result: Dictionary from static_analyzer.analyze_file()
            risk_result: Dictionary output representing Risk Evaluator score & classification 
            threat_intel_result: Dictionary output from ThreatIntelClient.lookup()
            
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
            "entropy": analysis_result.get("entropy", 0.0),
            "suspicious_imports": analysis_result.get("num_suspicious_imports", 0),
            "packed_flag": analysis_result.get("packed", False)
        }
        
        # Add additional analysis elements if they are present and useful 
        # (e.g., file_size, high_entropy_sections)
        if "file_size" in analysis_result:
            static_analysis["file_size"] = analysis_result["file_size"]
        if "high_entropy_sections" in analysis_result:
            static_analysis["high_entropy_sections"] = analysis_result["high_entropy_sections"]
            
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
