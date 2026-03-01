from typing import Dict, Any, Tuple, List

def evaluate_risk(analysis_result: Dict[str, Any]) -> Tuple[int, str, List[str]]:
    """
    Evaluates risk deterministically based on static analysis results.
    
    Args:
        analysis_result: Result dictionary from static_analyzer.analyze_file()
        
    Returns:
        Tuple containing:
        - risk_score (int): 0-100 score
        - classification (str): 'SAFE', 'SUSPICIOUS', or 'HIGH_RISK'
        - reasons (List[str]): List of reasons for the score
    """
    score = 0
    reasons = []

    # Check for invalid PE format
    if analysis_result.get("error") == "Not a valid PE file":
        score += 40
        reasons.append("Invalid PE format")
        
    # Check for empty/malformed (0 bytes)
    file_size = analysis_result.get("file_size", 0)
    if file_size == 0:
        score += 30
        reasons.append("Empty file")
    elif analysis_result.get("error") and analysis_result.get("error") != "Not a valid PE file":
        # General malformed error
        score += 30
        reasons.append(f"Analysis error: {analysis_result['error']}")

    # Check for suspicious imports
    num_suspicious = analysis_result.get("num_suspicious_imports", 0)
    if num_suspicious > 0:
        score += 20
        reasons.append(f"Suspicious import detected ({num_suspicious} imports)")

    # Check for high entropy sections
    high_entropy_sections = analysis_result.get("high_entropy_sections", 0)
    if high_entropy_sections > 0:
        score += 40
        reasons.append(f"High entropy section detected ({high_entropy_sections} sections)")

    # Cap score at 100
    score = min(score, 100)

    # Classification logic
    if score >= 60:
        classification = "HIGH_RISK"
    elif score >= 20:
        classification = "SUSPICIOUS"
    else:
        classification = "SAFE"
        
    # Add a safe reason if no flags
    if score == 0:
        reasons.append("No suspicious indicators found")

    return score, classification, reasons
