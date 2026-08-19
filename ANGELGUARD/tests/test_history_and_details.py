"""
tests/test_history_and_details.py

Step 6 — HistoryPanel and AnalysisDetailsDialog tests. Covers the
persist -> list_events -> select -> get_event -> display round trip, and
the "unknown reputation is never shown as safe/clean" requirement. Uses a
temp AdminEventLogger database, never the real one. Avoids brittle
pixel/screenshot assertions — reads widget text/data directly instead.
"""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from PyQt5.QtWidgets import QApplication

_app = QApplication.instance() or QApplication(sys.argv)

from event_logging.admin_event_logger import AdminEventLogger
from ui.history_panel import HistoryPanel, _EVENT_ID_COLUMN
from ui.analysis_details import AnalysisDetailsDialog


def _final_event(event_id, filename, score, level, ti=None, explanation=None, reasons=None):
    return {
        "event_id": event_id,
        "timestamp": "2026-03-06T18:20:00Z",
        "file": {
            "path": f"C:/Downloads/{filename}", "filename": filename,
            "size": 40960, "sha256": f"hash-{event_id}",
        },
        "static_analysis": {
            "num_sections": 3, "high_entropy_sections": 1, "total_imports": 20,
            "num_suspicious_imports": 2, "suspicious_imports": ["KERNEL32:VirtualAlloc"],
            "total_strings": 55,
            "sections": [{"name": ".text", "entropy": 7.8, "size": 4096}],
        },
        "risk": {"score": score, "level": level, "reasons": reasons if reasons is not None else ["Suspicious import detected"]},
        "threat_intelligence": ti if ti is not None else {"status": "unknown"},
        "explanation": explanation,
        "recommended_action": "Exercise caution.",
        "analysis_status": "completed",
    }


class TestHistoryRoundTrip:
    def test_persist_list_select_retrieve_display(self, tmp_path):
        logger = AdminEventLogger(db_path=str(tmp_path / "history.db"))
        event = _final_event("evt-hist-1", "tool.exe", 65, "SUSPICIOUS")
        logger.log_event(event)

        panel = HistoryPanel(logger, poll_interval_ms=0)  # no auto-refresh timer in tests
        panel.refresh()

        assert panel._table.rowCount() == 1
        assert panel._table.item(0, 1).text() == "tool.exe"  # Filename column
        assert panel._table.item(0, 2).text() == "SUSPICIOUS"  # Classification column
        assert panel._table.item(0, 3).text() == "65"  # Score column

        event_id = panel._table.item(0, _EVENT_ID_COLUMN).text()
        assert event_id == "evt-hist-1"

        retrieved = logger.get_event(event_id)
        assert retrieved is not None
        assert retrieved["file"]["filename"] == "tool.exe"
        assert retrieved["risk"]["score"] == 65

        # "Display details" — construct the dialog with the retrieved
        # event and confirm it renders the real data, not placeholder text.
        dialog = AnalysisDetailsDialog(retrieved)
        all_text = _all_label_text(dialog)
        assert "tool.exe" in all_text
        assert "65" in all_text
        assert "SUSPICIOUS" in all_text

    def test_history_shows_most_recent_events_first(self, tmp_path):
        logger = AdminEventLogger(db_path=str(tmp_path / "history.db"))
        for i in range(3):
            logger.log_event(_final_event(f"evt-{i}", f"file{i}.exe", 10 * i, "SAFE"))

        panel = HistoryPanel(logger, poll_interval_ms=0)
        panel.refresh()

        assert panel._table.rowCount() == 3
        ids_in_order = [panel._table.item(r, _EVENT_ID_COLUMN).text() for r in range(3)]
        assert ids_in_order == ["evt-2", "evt-1", "evt-0"]


class TestUnknownReputationNeverShownAsClean:
    def test_unknown_ti_status_renders_as_unknown_not_clean(self):
        event = _final_event(
            "evt-unknown-ti", "unverified.exe", 30, "SUSPICIOUS",
            ti={"status": "unknown"},
        )
        dialog = AnalysisDetailsDialog(event)
        all_text = _all_label_text(dialog).lower()

        assert "unknown" in all_text
        assert "clean" not in all_text
        # The only permitted use of "safe" here is the explicit disclaimer
        # that unknown reputation does NOT mean safe (Step 11) — there must
        # be no affirmative "safe"/"clean" verdict anywhere in the text.
        assert "does not mean the file is safe" in all_text
        assert "reputation: safe" not in all_text

    def test_known_malicious_ti_is_distinguished_from_unknown(self):
        event = _final_event(
            "evt-known-bad", "bad.exe", 90, "HIGH_RISK",
            ti={
                "virus_total_detections": 50, "virus_total_total_engines": 70,
                "malwarebazaar_match": True, "malware_family": "RedLine Stealer",
                "confidence": "high",
            },
        )
        dialog = AnalysisDetailsDialog(event)
        all_text = _all_label_text(dialog)

        assert "50/70" in all_text
        assert "KNOWN MATCH" in all_text
        assert "RedLine Stealer" in all_text


class TestAIUnavailableInDetailsView:
    def test_no_explanation_shows_unavailable_not_blank(self):
        event = _final_event("evt-no-ai", "sample.exe", 40, "SUSPICIOUS", explanation=None)
        dialog = AnalysisDetailsDialog(event)
        all_text = _all_label_text(dialog)
        assert "AI explanation unavailable." in all_text

    def test_real_explainer_fallback_dict_is_also_shown_as_unavailable(self):
        """Step 8 MVP-freeze audit finding: a real AIExplainer with no
        client configured returns a populated fallback dict (not None) —
        e.g. ai_summary='AI analysis unavailable (client not initialized).'
        This must render the same 'AI explanation unavailable.' message as
        the None case, matching ui/employee_guidance.py's popup, which
        already detects this exact fallback shape. Before this fix, the
        details view showed the fallback dict as if it were genuine AI
        content — not false information, but inconsistent with the popup."""
        event = _final_event(
            "evt-fallback-ai", "sample.exe", 40, "SUSPICIOUS",
            explanation={
                "ai_summary": "AI analysis unavailable (client not initialized).",
                "threat_explanation": "The AI service could not generate a threat explanation.",
                "recommended_action": "Exercise caution before executing this file.",
                "confidence": "unknown",
            },
        )
        dialog = AnalysisDetailsDialog(event)
        all_text = _all_label_text(dialog)
        assert "AI explanation unavailable." in all_text
        assert "The AI service could not generate" not in all_text  # not shown as genuine content


def _all_label_text(widget) -> str:
    from PyQt5.QtWidgets import QLabel
    return "\n".join(lbl.text() for lbl in widget.findChildren(QLabel))
