import logging
import requests
from config.settings import MB_API_URL, MB_API_KEY, VT_API_URL, VT_API_KEY

logger = logging.getLogger(__name__)

class ThreatIntelClient:
    """
    Threat Intelligence Client for ANGELGUARD Phase 6.1.
    Queries global reputation services (MalwareBazaar, VirusTotal) for file hashes.
    """
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        
    def check_malwarebazaar(self, file_hash: str) -> dict:
        """
        Query MalwareBazaar API for the given SHA256 hash.
        """
        data = {
            'query': 'get_info',
            'hash': file_hash
        }
        headers = {}
        if MB_API_KEY:
            headers['API-KEY'] = MB_API_KEY
            
        try:
            response = requests.post(MB_API_URL, data=data, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            result = response.json()
            
            if result.get('query_status') == 'ok':
                data_info = result.get('data', [{}])[0]
                return {
                    "malwarebazaar_match": True,
                    "malware_family": data_info.get("signature", "Unknown"),
                    "first_seen": data_info.get("first_seen", "Unknown"),
                }
            elif result.get('query_status') == 'hash_not_found':
                return {
                    "malwarebazaar_match": False,
                    "malware_family": "Unknown",
                }
            print(f"MalwareBazaar unexpected response: {result}")
            return {"status": "unknown"}
        except requests.RequestException as e:
            print(f"MalwareBazaar API query failed: {e}")
            return {"status": "unknown"}
        except ValueError as e:
            print(f"MalwareBazaar JSON decode failed: {e}")
            return {"status": "unknown"}

    def check_virustotal(self, file_hash: str) -> dict:
        """
        Query VirusTotal API (v3) for the given SHA256 hash.
        """
        if not VT_API_KEY:
            logger.warning("VirusTotal API Key is missing. Returning unknown.")
            return {"status": "unknown", "error": "Missing API Key"}
            
        url = f"{VT_API_URL}{file_hash}"
        headers = {
            "x-apikey": VT_API_KEY
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                result = response.json()
                stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                total = sum(stats.values()) if stats else 0
                return {
                    "virus_total_detections": malicious,
                    "virus_total_total_engines": total
                }
            elif response.status_code == 404:
                return {
                    "virus_total_detections": 0,
                    "virus_total_total_engines": 0,
                }
            else:
                logger.error(f"VirusTotal API returned status {response.status_code}")
                return {"status": "unknown"}
        except requests.RequestException as e:
            logger.error(f"VirusTotal API query failed: {e}")
            return {"status": "unknown"}
        except ValueError as e:
            logger.error(f"VirusTotal JSON decode failed: {e}")
            return {"status": "unknown"}

    def get_reputation(self, file_hash: str) -> dict:
        """
        Get combined reputation from all threat intel sources.
        """
        reputation_result = {
            "hash": file_hash,
            "virus_total_detections": 0,
            "virus_total_total_engines": 0,
            "malwarebazaar_match": False,
            "malware_family": "Unknown",
            "confidence": "low"
        }
        
        # Query MalwareBazaar
        mb_result = self.check_malwarebazaar(file_hash)
        mb_failed = False
        if mb_result.get("status") == "unknown":
            mb_failed = True
        else:
            reputation_result["malwarebazaar_match"] = mb_result.get("malwarebazaar_match", False)
            if reputation_result["malwarebazaar_match"]:
                reputation_result["malware_family"] = mb_result.get("malware_family", "Unknown")

        # Query VirusTotal
        vt_result = self.check_virustotal(file_hash)
        vt_failed = False
        if vt_result.get("status") == "unknown":
            vt_failed = True
        else:
            reputation_result["virus_total_detections"] = vt_result.get("virus_total_detections", 0)
            reputation_result["virus_total_total_engines"] = vt_result.get("virus_total_total_engines", 0)

        # If both APIs failed or VirusTotal fails due to missing keys, return status unknown
        # Wait, the instruction says "If API fails or is unavailable, return: {'status': 'unknown'}"
        # We will return unknown if BOTH APIs fail, or if VT has no API key and MB fails.
        if mb_failed and vt_failed:
            return {"status": "unknown"}

        # Calculate Confidence
        is_malicious = False
        if reputation_result["malwarebazaar_match"]:
            is_malicious = True
        if reputation_result.get("virus_total_detections", 0) >= 3:
            is_malicious = True
            
        if is_malicious:
            reputation_result["confidence"] = "high"
        elif reputation_result.get("virus_total_detections", 0) > 0:
            reputation_result["confidence"] = "medium"
            
        return reputation_result
