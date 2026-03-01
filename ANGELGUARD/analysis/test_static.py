"""
Test script for static analyzer.

Usage:
    python analysis/test_static.py <path_to_exe_file>

Example:
    python analysis/test_static.py C:\Users\user\Downloads\test.exe
"""

import sys
import os
import json

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from analysis.static_analyzer import analyze_file, get_analysis_summary


def main():
    """Main test function."""
    if len(sys.argv) < 2:
        print("Usage: python analysis/test_static.py <path_to_exe_file>")
        print("\nExample:")
        print("  python analysis/test_static.py C:/Users/user/Downloads/notepad.exe")
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
    print("ANGELGUARD Static Analyzer - Test Script")
    print("=" * 70)
    print(f"\nAnalyzing: {file_path}\n")
    
    try:
        # Perform analysis
        result = analyze_file(file_path)
        
        # Print summary
        print("\n" + get_analysis_summary(result))
        
        # Print full JSON output
        print("\n" + "=" * 70)
        print("Full JSON Output:")
        print("=" * 70)
        print(json.dumps(result, indent=2))
        
        # Check for errors
        if result.get("error"):
            print(f"\n⚠ Analysis completed with error: {result['error']}")
            sys.exit(1)
        else:
            print("\n✓ Analysis completed successfully!")
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\n✗ Fatal error during analysis: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
