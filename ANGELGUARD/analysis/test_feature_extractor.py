"""
Test script for feature extractor.

This script tests the feature extraction module by:
1. Running static analysis on a PE file
2. Extracting features from the analysis result
3. Displaying the ML-ready feature vector

Usage:
    python analysis/test_feature_extractor.py <path_to_exe_file>

Example:
    python analysis/test_feature_extractor.py C:/Windows/System32/notepad.exe
"""

import sys
import os
import json

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from analysis.static_analyzer import analyze_file
from analysis.feature_extractor import extract_features, features_to_vector, get_feature_summary


def main():
    """Main test function."""
    if len(sys.argv) < 2:
        print("Usage: python analysis/test_feature_extractor.py <path_to_exe_file>")
        print("\nExample:")
        print("  python analysis/test_feature_extractor.py C:/Windows/System32/notepad.exe")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    # Check if file exists
    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}")
        sys.exit(1)
    
    # Check if file is .exe
    if not file_path.lower().endswith('.exe'):
        print(f"Warning: File does not have .exe extension: {file_path}")
        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            sys.exit(0)
    
    print("=" * 70)
    print("ANGELGUARD Feature Extractor - Test Script")
    print("=" * 70)
    print(f"\nAnalyzing: {file_path}\n")
    
    try:
        # Step 1: Perform static analysis
        print("[Step 1] Running static analysis...")
        analysis_result = analyze_file(file_path)
        
        if analysis_result.get("error"):
            print(f"\nError: Static analysis failed - {analysis_result['error']}")
            print("Cannot extract features from invalid PE file.")
            sys.exit(1)
        
        print("\n[Step 2] Extracting ML-ready features...")
        
        # Step 2: Extract features
        features = extract_features(analysis_result)
        
        if features is None:
            print("\nError: Feature extraction failed (invalid PE or analysis error)")
            sys.exit(1)
        
        # Step 3: Convert to vector
        feature_vector = features_to_vector(features)
        
        # Display results
        print("\n" + get_feature_summary(features))
        
        print("\n" + "=" * 70)
        print("Feature Dictionary (JSON):")
        print("=" * 70)
        print(json.dumps(features, indent=2))
        
        print("\n" + "=" * 70)
        print("Feature Vector (for ML model):")
        print("=" * 70)
        print(feature_vector)
        print(f"\nVector length: {len(feature_vector)} features")
        print("\nFeature order:")
        feature_names = [
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
        for i, name in enumerate(feature_names):
            print(f"  [{i}] {name}: {feature_vector[i]}")
        
        print("\n✓ Feature extraction completed successfully!")
        sys.exit(0)
            
    except KeyboardInterrupt:
        print("\n\nFeature extraction interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\n✗ Fatal error during feature extraction: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
