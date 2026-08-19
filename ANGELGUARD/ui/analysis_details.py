"""
ui/analysis_details.py

Step 6 — read-only detail view for one canonical analysis event: the exact
shape AnalysisPipeline._build_final_event, AdminEventLogger.get_event, and
AdminEventLogger.list_events all produce/return. Never computes or infers
risk itself — every value shown is read directly from the event dict.
Explicitly distinguishes KNOWN data from UNKNOWN/NOT AVAILABLE; missing
threat intelligence or AI explanation is never rendered as a clean/safe
verdict (see DECISIONS.md Step 6).
"""
from typing import Any, Dict, Optional

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame,
    QScrollArea, QWidget,
)
from PyQt5.QtGui import QFont

_RISK_COLORS = {
    "SAFE": "#2e7d32",
    "SUSPICIOUS": "#f57c00",
    "HIGH_RISK": "#d32f2f",
}


def _section_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet("font-weight: bold; color: #1565c0; margin-top: 12px; font-size: 13px;")
    return lbl


def _kv_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setWordWrap(True)
    lbl.setStyleSheet("font-size: 12px;")
    return lbl


def _fmt_size(size: Optional[int]) -> str:
    if size is None:
        return "Unknown"
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


class AnalysisDetailsDialog(QDialog):
    """Read-only. Shows a single canonical event in full: file, risk,
    static analysis, threat intelligence, explanation, recommendation."""

    def __init__(self, event: Dict[str, Any], parent=None):
        super().__init__(parent)
        self._event = event
        self.setWindowTitle("ANGELGUARD — Analysis Details")
        self.setMinimumSize(520, 600)
        self._build_ui()

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 20, 20, 20)
        outer.setSpacing(10)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setSpacing(6)

        event = self._event
        risk = event.get("risk") or {}
        file_info = event.get("file") or {}
        static = event.get("static_analysis") or {}
        ti = event.get("threat_intelligence") or {}
        explanation = event.get("explanation")

        level = risk.get("level") or "UNKNOWN"

        title = QLabel(file_info.get("filename") or "Unknown file")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        layout.addWidget(title)

        badge = QLabel(level)
        badge.setStyleSheet(
            f"font-weight: bold; color: white; background-color: {_RISK_COLORS.get(level, '#666')};"
            "border-radius: 4px; padding: 4px 10px; font-size: 12px;"
        )
        layout.addWidget(badge)

        layout.addWidget(self._divider())
        layout.addWidget(_section_label("FILE"))
        layout.addWidget(_kv_label(f"Path: {file_info.get('path') or 'Unknown'}"))
        layout.addWidget(_kv_label(f"Size: {_fmt_size(file_info.get('size'))}"))
        layout.addWidget(_kv_label(f"SHA-256: {file_info.get('sha256') or 'Unknown'}"))
        layout.addWidget(_kv_label(f"Analyzed: {event.get('timestamp') or 'Unknown'}"))
        layout.addWidget(_kv_label(f"Event ID: {event.get('event_id') or 'Not available'}"))

        layout.addWidget(self._divider())
        layout.addWidget(_section_label("RISK"))
        score = risk.get("score")
        layout.addWidget(_kv_label(f"Score: {score if score is not None else 'Not available'}/100"))
        layout.addWidget(_kv_label(f"Classification: {level}"))
        reasons = risk.get("reasons") or []
        reasons_text = "\n".join(f"  • {r}" for r in reasons) if reasons else "  (no specific indicators recorded)"
        layout.addWidget(_kv_label(f"Why:\n{reasons_text}"))

        layout.addWidget(self._divider())
        layout.addWidget(_section_label("STATIC ANALYSIS"))
        if not static:
            layout.addWidget(_kv_label("Not available — analysis did not reach this stage."))
        else:
            error = static.get("error")
            layout.addWidget(_kv_label(
                f"PE validity: INVALID — {error}" if error else "PE validity: Valid PE file"
            ))
            layout.addWidget(_kv_label(f"Sections: {static.get('num_sections', 'Unknown')}"))
            layout.addWidget(_kv_label(f"High-entropy sections: {static.get('high_entropy_sections', 'Unknown')}"))
            sections = static.get("sections") or []
            if sections:
                lines = []
                for s in sections:
                    entropy = s.get("entropy")
                    entropy_str = f"{entropy:.2f}" if isinstance(entropy, (int, float)) else "Unknown"
                    lines.append(f"  • {s.get('name')}: entropy {entropy_str}, {s.get('size')} bytes")
                layout.addWidget(_kv_label("Section detail:\n" + "\n".join(lines)))
            layout.addWidget(_kv_label(f"Total imports: {static.get('total_imports', 'Unknown')}"))
            susp = static.get("suspicious_imports") or []
            layout.addWidget(_kv_label(
                "Suspicious imports: " + (", ".join(susp) if susp else "None detected")
            ))
            layout.addWidget(_kv_label(f"Strings extracted: {static.get('total_strings', 'Unknown')}"))

        layout.addWidget(self._divider())
        layout.addWidget(_section_label("THREAT INTELLIGENCE"))
        if not ti or ti.get("status") == "unknown":
            layout.addWidget(_kv_label(
                "Reputation: UNKNOWN — threat intelligence services were unavailable "
                "or returned no data. This does NOT mean the file is safe."
            ))
        else:
            vt_det = ti.get("virus_total_detections")
            vt_total = ti.get("virus_total_total_engines")
            if vt_det is not None:
                vt_text = f"VirusTotal: {vt_det}/{vt_total} engines flagged this file" if vt_total else f"VirusTotal: {vt_det} detections"
            else:
                vt_text = "VirusTotal: Not available"
            layout.addWidget(_kv_label(vt_text))

            mb_match = ti.get("malwarebazaar_match")
            if mb_match is None:
                mb_text = "MalwareBazaar: Not available"
            elif mb_match:
                mb_text = f"MalwareBazaar: KNOWN MATCH — family: {ti.get('malware_family', 'Unknown')}"
            else:
                mb_text = "MalwareBazaar: No known match"
            layout.addWidget(_kv_label(mb_text))

            if ti.get("confidence"):
                layout.addWidget(_kv_label(f"Confidence: {ti.get('confidence')}"))

        layout.addWidget(self._divider())
        layout.addWidget(_section_label("AI EXPLANATION"))
        if not explanation:
            layout.addWidget(_kv_label("AI explanation unavailable."))
        else:
            layout.addWidget(_kv_label(f"Summary: {explanation.get('ai_summary', 'Not available')}"))
            if explanation.get("threat_explanation"):
                layout.addWidget(_kv_label(f"Details: {explanation.get('threat_explanation')}"))
            if explanation.get("confidence"):
                layout.addWidget(_kv_label(f"AI confidence: {explanation.get('confidence')}"))

        layout.addWidget(self._divider())
        layout.addWidget(_section_label("RECOMMENDATION"))
        rec = event.get("recommended_action") or "Review this file manually before executing it."
        rec_label = _kv_label(rec)
        rec_label.setStyleSheet("font-size: 13px; font-weight: bold;")
        layout.addWidget(rec_label)

        layout.addStretch()
        scroll.setWidget(content)
        outer.addWidget(scroll)

        close_row = QHBoxLayout()
        close_row.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        close_row.addWidget(close_btn)
        outer.addLayout(close_row)

    @staticmethod
    def _divider() -> QFrame:
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        return line
