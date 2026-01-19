import pefile
import math

def calculate_entropy(data):
    if not data:
        return 0.0

    entropy = 0
    length = len(data)
    for x in range(256):
        p_x = data.count(bytes([x])) / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy

def analyze_file(path):
    report = {
        "path": path,
        "is_pe": False,
        "imports": [],
        "entropy": 0.0,
    }

    try:
        pe = pefile.PE(path)
        report["is_pe"] = True

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                report["imports"].append(entry.dll.decode(errors="ignore"))

        for section in pe.sections:
            report["entropy"] = max(
                report["entropy"],
                section.get_entropy()
            )

    except Exception as e:
        report["error"] = str(e)

    return report
