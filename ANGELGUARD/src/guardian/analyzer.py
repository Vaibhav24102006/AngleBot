import pefile
import hashlib
import math
import os
from src.utils.logger import guardian_logger

class StaticAnalyzer:
    def __init__(self):
        pass

    def calculate_hash(self, file_path, msg_digest):
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    msg_digest.update(chunk)
            return msg_digest.hexdigest()
        except Exception as e:
            guardian_logger.logger.error(f"Error hashing file: {e}")
            return None

    def calculate_entropy(self, data):
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def analyze(self, file_path):
        results = {
            "file_path": file_path,
            "sha256": self.calculate_hash(file_path, hashlib.sha256()),
            "is_pe": False,
            "entropy": 0,
            "imports": [],
            "sections": []
        }

        try:
            # Basic file entropy
            with open(file_path, "rb") as f:
                data = f.read()
                results["entropy"] = self.calculate_entropy(data)

            # PE Analysis
            if file_path.lower().endswith(('.exe', '.dll', '.sys')):
                pe = pefile.PE(file_path)
                results["is_pe"] = True
                
                # DLL Imports
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode('utf-8', errors='ignore')
                        results["imports"].append(dll_name)
                
                # Sections
                for section in pe.sections:
                    sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                    results["sections"].append({
                        "name": sec_name,
                        "entropy": section.get_entropy()
                    })
                pe.close()

        except pefile.PEFormatError:
            guardian_logger.logger.warning(f"Not a valid PE file: {file_path}")
        except Exception as e:
            guardian_logger.logger.error(f"Analysis failed: {e}")

        return results
