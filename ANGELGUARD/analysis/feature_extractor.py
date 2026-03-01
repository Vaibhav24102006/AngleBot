"""
Feature Extraction Module

This module converts raw static analysis output into machine-learning-ready numerical features.
It performs feature engineering to transform metadata into normalized, meaningful features
for ML model training and prediction.

Academic Project: ANGELGUARD - AI-Driven Endpoint Security Guardian
"""

import math
from typing import Dict, Optional, Any, List


def extract_features(analysis_result: Dict[str, Any]) -> Optional[Dict[str, float]]:
    """
    Extract ML-ready numerical features from static analysis results.
    
    This function performs feature engineering to convert raw analysis data
    into normalized numerical features suitable for machine learning models.
    
    Feature Engineering Rationale:
    - Log transformation of file size prevents large files from dominating the model
    - Ratios (suspicious imports, high entropy) provide normalized indicators
    - Entropy metrics detect packing/obfuscation
    - String density indicates code complexity
    - Packed flag is a derived binary indicator based on entropy patterns
    
    Args:
        analysis_result: Dictionary from static_analyzer.analyze() containing:
            {
                "file_size": int,
                "hash": str,
                "total_imports": int,
                "suspicious_imports": List[str],
                "num_suspicious_imports": int,
                "num_sections": int,
                "high_entropy_sections": int,
                "total_strings": int,
                "sections": List[Dict],
                "error": Optional[str]
            }
        
    Returns:
        Dictionary with ML-ready numerical features:
        {
            "file_size_log": float,
            "import_count": int,
            "suspicious_import_ratio": float,
            "section_count": int,
            "high_entropy_ratio": float,
            "avg_section_entropy": float,
            "max_section_entropy": float,
            "string_density": float,
            "packed_flag": int (0 or 1)
        }
        
        Returns None if analysis_result contains an error or is invalid.
    """
    # Check for errors in analysis result
    if analysis_result is None:
        return None
    
    if analysis_result.get("error") is not None:
        return None
    
    # Extract base values with safe defaults
    file_size = analysis_result.get("file_size", 0)
    total_imports = analysis_result.get("total_imports", 0)
    num_suspicious_imports = analysis_result.get("num_suspicious_imports", 0)
    num_sections = analysis_result.get("num_sections", 0)
    high_entropy_sections = analysis_result.get("high_entropy_sections", 0)
    total_strings = analysis_result.get("total_strings", 0)
    sections = analysis_result.get("sections", [])
    
    # Initialize features dictionary
    features = {}
    
    # Feature 1: file_size_log
    # Log transformation prevents large files from dominating the model
    # Adding 1 to handle zero-size files and ensure log is defined
    features["file_size_log"] = math.log(file_size + 1)
    
    # Feature 2: import_count
    # Total number of imported APIs
    features["import_count"] = total_imports
    
    # Feature 3: suspicious_import_ratio
    # Ratio of suspicious imports to total imports
    # Indicates likelihood of malicious behavior
    if total_imports > 0:
        features["suspicious_import_ratio"] = num_suspicious_imports / total_imports
    else:
        features["suspicious_import_ratio"] = 0.0
    
    # Feature 4: section_count
    # Total number of PE sections
    features["section_count"] = num_sections
    
    # Feature 5: high_entropy_ratio
    # Ratio of high entropy sections to total sections
    # High entropy often indicates packing or encryption
    if num_sections > 0:
        features["high_entropy_ratio"] = high_entropy_sections / num_sections
    else:
        features["high_entropy_ratio"] = 0.0
    
    # Feature 6 & 7: avg_section_entropy and max_section_entropy
    # Calculate entropy statistics from section data
    if sections and len(sections) > 0:
        entropies = []
        for section in sections:
            entropy = section.get("entropy", 0.0)
            if isinstance(entropy, (int, float)):
                entropies.append(float(entropy))
        
        if entropies:
            features["avg_section_entropy"] = sum(entropies) / len(entropies)
            features["max_section_entropy"] = max(entropies)
        else:
            features["avg_section_entropy"] = 0.0
            features["max_section_entropy"] = 0.0
    else:
        features["avg_section_entropy"] = 0.0
        features["max_section_entropy"] = 0.0
    
    # Feature 8: string_density
    # Ratio of strings to file size
    # Indicates code complexity and readability
    if file_size > 0:
        features["string_density"] = total_strings / file_size
    else:
        features["string_density"] = 0.0
    
    # Feature 9: packed_flag
    # Binary indicator: 1 if file appears packed, 0 otherwise
    # Packed files have high entropy ratios or very high max entropy
    high_entropy_ratio = features["high_entropy_ratio"]
    max_section_entropy = features["max_section_entropy"]
    
    if high_entropy_ratio > 0.5 or max_section_entropy > 7.5:
        features["packed_flag"] = 1
    else:
        features["packed_flag"] = 0
    
    return features


def features_to_vector(features: Optional[Dict[str, float]]) -> Optional[List[float]]:
    """
    Convert feature dictionary to ordered numerical vector for ML model.
    
    This function ensures consistent feature ordering required by ML models.
    The order must match the training data feature order.
    
    Args:
        features: Feature dictionary from extract_features()
        
    Returns:
        List of float values in fixed order:
        [
            file_size_log,
            import_count,
            suspicious_import_ratio,
            section_count,
            high_entropy_ratio,
            avg_section_entropy,
            max_section_entropy,
            string_density,
            packed_flag
        ]
        
        Returns None if features is None.
    """
    if features is None:
        return None
    
    # Define feature order (must match training data)
    feature_order = [
        "file_size_log",
        "import_count",
        "suspicious_import_ratio",
        "section_count",
        "high_entropy_ratio",
        "avg_section_entropy",
        "max_section_entropy",
        "string_density",
        "packed_flag"
    ]
    
    # Extract features in order
    vector = []
    for feature_name in feature_order:
        value = features.get(feature_name, 0.0)
        # Ensure all values are float
        vector.append(float(value))
    
    return vector


def get_feature_summary(features: Optional[Dict[str, float]]) -> str:
    """
    Generate a human-readable summary of extracted features.
    
    Args:
        features: Feature dictionary from extract_features()
        
    Returns:
        Formatted summary string
    """
    if features is None:
        return "Error: No features extracted (invalid PE file or analysis error)"
    
    summary = f"""
=== Feature Extraction Summary ===

File Characteristics:
  File Size (log): {features.get('file_size_log', 0):.3f}
  Section Count: {features.get('section_count', 0)}
  Import Count: {features.get('import_count', 0)}

Risk Indicators:
  Suspicious Import Ratio: {features.get('suspicious_import_ratio', 0):.3f}
  High Entropy Ratio: {features.get('high_entropy_ratio', 0):.3f}
  Packed Flag: {features.get('packed_flag', 0)}

Entropy Metrics:
  Average Section Entropy: {features.get('avg_section_entropy', 0):.3f}
  Maximum Section Entropy: {features.get('max_section_entropy', 0):.3f}

Code Characteristics:
  String Density: {features.get('string_density', 0):.6f}
"""
    
    return summary
