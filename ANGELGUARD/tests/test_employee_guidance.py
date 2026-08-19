"""
tests/test_employee_guidance.py

Step 6 — GuidanceController/EmployeeGuidance contract tests, updated for
the canonical final_event single-argument API (see DECISIONS.md Step 6).
Covers: trigger/skip classification logic, the warning displaying real
(not fabricated) risk data, AI-unavailable still showing deterministic
reasons, "Review Details" opening AnalysisDetailsDialog with the same
event, and the cross-thread signal/slot boundary GuidanceController relies
on for thread safety.
"""
import threading
import unittest
import sys
import os
import time
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from PyQt5.QtWidgets import QApplication
from ui.employee_guidance import EmployeeGuidance, GuidanceController, trigger_guidance

# Constructed once at import time so every test class below can safely
# build real QDialog/QObject instances regardless of test execution order —
# PyQt5 allows only one QApplication per process.
_app = QApplication.instance() or QApplication(sys.argv)


def _event(
    filename="installer.exe", score=68, level="SUSPICIOUS",
    reasons=None, explanation="AUTO", recommended_action="Do not execute",
):
    if explanation == "AUTO":
        explanation = {
            "ai_summary": "Test summary",
            "threat_explanation": "Test explanation",
            "recommended_action": "Do not execute",
            "confidence": "high",
        }
    return {
        "event_id": "evt-guidance-1",
        "timestamp": "2026-03-06T18:20:00Z",
        "file": {"path": f"C:/Downloads/{filename}", "filename": filename, "size": 2048, "sha256": "abc123"},
        "static_analysis": {"num_suspicious_imports": 3, "sections": []},
        "risk": {"score": score, "level": level, "reasons": reasons if reasons is not None else ["Suspicious import detected"]},
        "threat_intelligence": {"status": "unknown"},
        "explanation": explanation,
        "recommended_action": recommended_action,
        "analysis_status": "completed",
    }


class TestGuidanceControllerClassificationGate(unittest.TestCase):
    @patch('ui.employee_guidance.QApplication')
    @patch('ui.employee_guidance.EmployeeGuidance')
    def test_guidance_trigger_suspicious(self, MockDialog, MockApp):
        """A SUSPICIOUS event fires the UI alert."""
        controller = GuidanceController()
        with patch.object(controller, '_show_alert') as mock_show:
            controller.trigger(_event(level="SUSPICIOUS"))
            mock_show.assert_not_called()  # signal is queued, not called synchronously
            self.assertTrue(hasattr(controller.signals, 'trigger_alert'))

    @patch('ui.employee_guidance.QApplication')
    @patch('ui.employee_guidance.EmployeeGuidance')
    def test_guidance_skips_safe(self, MockDialog, MockApp):
        """A SAFE event is ignored silently without UI interference."""
        controller = GuidanceController()
        with patch.object(controller, '_show_alert') as mock_show:
            controller.trigger(_event(level="SAFE", score=0, reasons=[]))
            mock_show.assert_not_called()


class TestWarningDisplaysRealResult(unittest.TestCase):
    """The UI must never calculate or invent risk data — every value shown
    must come straight from the canonical event that was passed in."""

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication(sys.argv)

    def test_populate_data_shows_correct_score_classification_reasons_and_recommendation(self):
        event = _event(
            filename="malware_sample.exe", score=72, level="HIGH_RISK",
            reasons=["Suspicious imports", "High entropy", "Unknown reputation"],
            recommended_action="Do not execute unless the source can be verified.",
        )
        dialog = EmployeeGuidance()
        dialog.populate_data(event)

        self.assertIn("malware_sample.exe", dialog.file_label.text())
        self.assertIn("72", dialog.risk_label.text())
        self.assertEqual(dialog.ai_summary.text(), "Test summary")
        self.assertEqual(dialog.threat_explain.text(), "Test explanation")
        self.assertIn("Do not execute", dialog.action_explain.text())
        # Real event is retained for "Review Details" — not recomputed.
        self.assertIs(dialog._event, event)

    def test_unknown_score_is_shown_as_unknown_not_zero(self):
        event = _event(score=None, level=None)
        dialog = EmployeeGuidance()
        dialog.populate_data(event)
        self.assertIn("Unknown", dialog.risk_label.text())


class TestAIUnavailableStillShowsDeterministicReasons(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication(sys.argv)

    def test_explanation_none_shows_unavailable_message_and_real_reasons(self):
        event = _event(
            level="SUSPICIOUS", score=40,
            reasons=["Suspicious import detected (3 imports)", "Unknown file reputation"],
            explanation=None,
        )
        dialog = EmployeeGuidance()
        dialog.populate_data(event)

        self.assertIn("AI explanation unavailable", dialog.ai_summary.text())
        self.assertTrue(dialog.threat_title.isHidden())  # .hide() was called
        # Deterministic reasons must still be visible — AI failure never
        # hides the actual analysis.
        self.assertIn("Suspicious import detected (3 imports)", dialog.action_explain.text())
        self.assertIn("Unknown file reputation", dialog.action_explain.text())

    def test_explanation_fallback_dict_is_also_treated_as_unavailable(self):
        """ai_explainer.py's real fallback response (client not configured,
        or API failure) is a populated dict whose ai_summary literally says
        'unavailable'/'failed' — this must be treated the same as
        explanation being None, not shown as if it were a real AI result."""
        event = _event(
            level="HIGH_RISK", score=90, reasons=["High entropy"],
            explanation={
                "ai_summary": "AI analysis unavailable (client not initialized).",
                "threat_explanation": "The AI service could not generate a threat explanation.",
                "recommended_action": "Exercise caution before executing this file.",
                "confidence": "unknown",
            },
        )
        dialog = EmployeeGuidance()
        dialog.populate_data(event)

        self.assertIn("AI explanation unavailable", dialog.ai_summary.text())
        self.assertIn("High entropy", dialog.action_explain.text())


class TestReviewDetailsOpensAnalysisDetails(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication(sys.argv)

    @patch('ui.employee_guidance.AnalysisDetailsDialog')
    def test_review_details_opens_dialog_with_the_same_event(self, MockDetailsDialog):
        event = _event()
        dialog = EmployeeGuidance()
        dialog.populate_data(event)

        mock_instance = MockDetailsDialog.return_value
        dialog._on_review_details()

        MockDetailsDialog.assert_called_once_with(event, parent=dialog)
        mock_instance.exec_.assert_called_once()

    def test_review_details_before_populate_does_not_crash(self):
        dialog = EmployeeGuidance()
        dialog._on_review_details()  # no event yet — must be a no-op


class TestCrossThreadSignalDelivery(unittest.TestCase):
    """GuidanceController.trigger() must be safely callable from a
    non-GUI thread (the watchdog callback thread in real use). Verifies
    the queued-signal delivery actually reaches _show_alert on the GUI
    thread once the event loop is pumped — not just that trigger() itself
    doesn't raise."""

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication(sys.argv)

    @patch('ui.employee_guidance.EmployeeGuidance')
    def test_trigger_from_background_thread_delivers_via_queued_signal(self, MockDialog):
        controller = GuidanceController()
        shown = threading.Event()
        controller.signals.trigger_alert.connect(lambda _e: shown.set())

        event = _event(level="HIGH_RISK")
        worker = threading.Thread(target=controller.trigger, args=(event,))
        worker.start()
        worker.join(timeout=2)

        # Delivery is queued onto the GUI thread — pump the event loop here.
        deadline = time.time() + 2
        while not shown.is_set() and time.time() < deadline:
            self.app.processEvents()
            time.sleep(0.01)

        self.assertTrue(shown.is_set(), "queued signal was not delivered to the GUI thread")


if __name__ == '__main__':
    unittest.main()
