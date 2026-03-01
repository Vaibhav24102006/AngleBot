"""
Advanced Static PE Analysis Engine

This module performs comprehensive static analysis on Windows PE (Portable Executable) files
without executing them. It extracts malware-relevant features for ML-based risk assessment.

Academic Project: ANGELGUARD - AI-Driven Endpoint Security Guardian
"""

import os
import hashlib
import math
import pefile
from typing import Dict, List, Optional, Any


# Predefined list of suspicious APIs commonly used in malware
SUSPICIOUS_APIS = [
    "VirtualAlloc",
    "VirtualProtect",
    "CreateRemoteThread",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "LoadLibraryA",
    "GetProcAddress",
    "WinExec",
    "ShellExecuteA",
    "URLDownloadToFileA",
    "ShellExecuteExA",
    "CreateProcessA",
    "CreateProcessW",
    "SetWindowsHookEx",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "RegSetValueEx",
    "RegSetValueExA",
    "RegSetValueExW",
    "NtCreateThreadEx",
    "ZwCreateThreadEx"
]


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of binary data.
    
    Entropy measures the randomness/uncertainty in data.
    High entropy (> 7.5) often indicates packing or encryption.
    
    Args:
        data: Binary data bytes
        
    Returns:
        Entropy value between 0.0 and 8.0
    """
    if not data or len(data) == 0:
        return 0.0
    
    entropy = 0.0
    length = len(data)
    
    # Count frequency of each byte value (0-255)
    for x in range(256):
        p_x = data.count(bytes([x])) / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    
    return entropy


def extract_ascii_strings(data: bytes, min_length: int = 4) -> List[str]:
    """
    Extract ASCII strings from binary data.
    
    Strings are sequences of printable ASCII characters (32-126).
    Useful for detecting API names, URLs, file paths, etc.
    
    Args:
        data: Binary data to scan
        min_length: Minimum string length to extract
        
    Returns:
        List of extracted ASCII strings
    """
    strings = []
    current_string = ""
    
    for byte in data:
        if 32 <= byte <= 126:  # Printable ASCII range
            current_string += chr(byte)
        else:
            if len(current_string) >= min_length:
                strings.append(current_string)
            current_string = ""
    
    # Handle string at end of data
    if len(current_string) >= min_length:
        strings.append(current_string)
    
    return strings


def analyze_file(file_path: str) -> Dict[str, Any]:
    """
    Perform comprehensive static analysis on a PE file.
    
    This is the main analysis function that orchestrates all analysis steps:
    1. File hash calculation
    2. PE structure parsing
    3. Import analysis
    4. Section analysis
    5. String extraction
    
    Args:
        file_path: Path to the .exe file to analyze
        
    Returns:
        Structured dictionary containing all analysis results:
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
        
        If file is not a valid PE:
        {
            "error": "Not a valid PE file",
            "file_size": int,
            "hash": str
        }
    """
    result = {
        "file_size": 0,
        "hash": "",
        "total_imports": 0,
        "suspicious_imports": [],
        "num_suspicious_imports": 0,
        "num_sections": 0,
        "high_entropy_sections": 0,
        "total_strings": 0,
        "sections": [],
        "error": None
    }
    
    try:
        # Step 1: Get file size
        result["file_size"] = os.path.getsize(file_path)
        
        # Step 2: Calculate SHA-256 hash
        print(f"[StaticAnalyzer] Calculating hash for: {file_path}")
        with open(file_path, "rb") as f:
            file_data = f.read()
            hash_obj = hashlib.sha256(file_data)
            result["hash"] = hash_obj.hexdigest()
        
        print(f"[StaticAnalyzer] File size: {result['file_size']} bytes")
        print(f"[StaticAnalyzer] SHA-256: {result['hash']}")
        
        # Step 3: Parse PE file structure
        print("[StaticAnalyzer] Parsing PE structure...")
        try:
            pe = pefile.PE(file_path)
        except pefile.PEFormatError as e:
            result["error"] = "Not a valid PE file"
            print(f"[StaticAnalyzer] Error: {result['error']} - {str(e)}")
            return result
        except Exception as e:
            result["error"] = f"PE parsing error: {str(e)}"
            print(f"[StaticAnalyzer] Error: {result['error']}")
            return result
        
        # Step 4: Extract imported APIs
        print("[StaticAnalyzer] Extracting imports...")
        all_imports = []
        suspicious_imports = []
        
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dll_name = entry.dll.decode(errors="ignore")
                    
                    # Extract APIs from this DLL
                    for imp in entry.imports:
                        if imp.name:
                            api_name = imp.name.decode(errors="ignore")
                            full_import = f"{dll_name}:{api_name}"
                            all_imports.append(full_import)
                            
                            # Check if API is suspicious
                            for suspicious_api in SUSPICIOUS_APIS:
                                if suspicious_api.lower() == api_name.lower():
                                    suspicious_imports.append(full_import)
                                    break
                except Exception as e:
                    print(f"[StaticAnalyzer] Warning: Error processing import entry: {e}")
                    continue
        
        result["total_imports"] = len(all_imports)
        result["suspicious_imports"] = suspicious_imports
        result["num_suspicious_imports"] = len(suspicious_imports)
        
        print(f"[StaticAnalyzer] Total imports: {result['total_imports']}")
        print(f"[StaticAnalyzer] Suspicious imports: {result['num_suspicious_imports']}")
        
        # Step 5: Analyze PE sections
        print("[StaticAnalyzer] Analyzing sections...")
        sections_data = []
        high_entropy_count = 0
        
        for section in pe.sections:
            try:
                section_name = section.Name.decode(errors="ignore").rstrip('\x00')
                section_size = section.SizeOfRawData
                
                # Calculate section entropy
                section_data = section.get_data()
                section_entropy = calculate_entropy(section_data) if section_data else 0.0
                
                # Use pefile's built-in entropy if available, otherwise use calculated
                try:
                    section_entropy = section.get_entropy()
                except:
                    pass  # Use our calculated entropy
                
                is_high_entropy = section_entropy > 7.5
                if is_high_entropy:
                    high_entropy_count += 1
                
                sections_data.append({
                    "name": section_name,
                    "entropy": round(section_entropy, 3),
                    "size": section_size
                })
                
            except Exception as e:
                print(f"[StaticAnalyzer] Warning: Error processing section: {e}")
                continue
        
        result["num_sections"] = len(pe.sections)
        result["high_entropy_sections"] = high_entropy_count
        result["sections"] = sections_data
        
        print(f"[StaticAnalyzer] Total sections: {result['num_sections']}")
        print(f"[StaticAnalyzer] High entropy sections (>7.5): {result['high_entropy_sections']}")
        
        # Step 6: Extract ASCII strings
        print("[StaticAnalyzer] Extracting ASCII strings...")
        try:
            strings = extract_ascii_strings(file_data, min_length=4)
            result["total_strings"] = len(strings)
            print(f"[StaticAnalyzer] Total strings extracted: {result['total_strings']}")
        except Exception as e:
            print(f"[StaticAnalyzer] Warning: Error extracting strings: {e}")
            result["total_strings"] = 0
        
        print("[StaticAnalyzer] Analysis complete!")
        
    except FileNotFoundError:
        result["error"] = f"File not found: {file_path}"
        print(f"[StaticAnalyzer] Error: {result['error']}")
    except PermissionError:
        result["error"] = f"Permission denied: {file_path}"
        print(f"[StaticAnalyzer] Error: {result['error']}")
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"
        print(f"[StaticAnalyzer] Error: {result['error']}")
        import traceback
        traceback.print_exc()
    
    return result


def get_analysis_summary(analysis_result: Dict[str, Any]) -> str:
    """
    Generate a human-readable summary of analysis results.
    
    Args:
        analysis_result: Result dictionary from analyze_file()
        
    Returns:
        Formatted summary string
    """
    if analysis_result.get("error"):
        return f"Error: {analysis_result['error']}\nFile size: {analysis_result.get('file_size', 0)} bytes\nHash: {analysis_result.get('hash', 'N/A')}"
    
    summary = f"""
=== Static Analysis Summary ===
File Size: {analysis_result.get('file_size', 0):,} bytes
SHA-256: {analysis_result.get('hash', 'N/A')}

Imports:
  Total: {analysis_result.get('total_imports', 0)}
  Suspicious: {analysis_result.get('num_suspicious_imports', 0)}

Sections:
  Total: {analysis_result.get('num_sections', 0)}
  High Entropy (>7.5): {analysis_result.get('high_entropy_sections', 0)}

Strings:
  Total ASCII strings: {analysis_result.get('total_strings', 0)}

Suspicious APIs Found:
"""
    for imp in analysis_result.get('suspicious_imports', [])[:10]:  # Show first 10
        summary += f"  - {imp}\n"
    
    if len(analysis_result.get('suspicious_imports', [])) > 10:
        summary += f"  ... and {len(analysis_result.get('suspicious_imports', [])) - 10} more\n"
    
    return summary
