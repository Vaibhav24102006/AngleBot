import sys
import os
import json
import logging
import requests

# Add project root to python path to allow importing modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from threat_intel.threat_intel_client import ThreatIntelClient

def run_test(file_hash: str):
    print(f"Testing Threat Intelligence Lookup for Hash: {file_hash}")
    
    client = ThreatIntelClient()
    result = client.get_reputation(file_hash)
    
    if result.get("status") == "unknown":
        print("\nThreat Intelligence Report")
        print("-" * 26)
        print("Status: Unknown (API unavailable or invalid configuration)")
        print("-" * 26)
        print("\nRaw JSON output:")
        print(json.dumps(result, indent=2))
        return

    print("\nThreat Intelligence Report")
    print("-" * 26)
    
    vt_det = result.get('virus_total_detections', 0)
    vt_tot = result.get('virus_total_total_engines', 0)
    print(f"VirusTotal detections: {vt_det}")
        
    mb_match = "match found" if result.get('malwarebazaar_match') else "no match"
    print(f"MalwareBazaar: {mb_match}")
    
    print(f"Malware family: {result.get('malware_family', 'Unknown')}")
    print(f"Confidence: {result.get('confidence', 'Unknown').capitalize()}")
    print("-" * 26)
    
    print("\nRaw JSON output:")
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        test_hash = sys.argv[1]
    else:
        print("No hash provided. Using a well-known test hash (WannaCry).")
        test_hash = "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"
        
    run_test(test_hash)
