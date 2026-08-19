"""
tests/test_security_invariants.py

Step 7 — explicit regression tests for ANGELGUARD's core security
invariants, consolidated in one place so they're easy to find and hard to
accidentally regress:

1. No execution of an analyzed file, anywhere in the pipeline-relevant
   source tree.
2. No automatic deletion of an analyzed file.
3. No automatic modification of an analyzed file.
4. Unknown threat intelligence / AI unavailability is never rendered as a
   "clean"/"safe" verdict.
5. event_id identity is preserved across pipeline -> persistence ->
   retrieval -> UI.
"""
import os
import sys
import re

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from PyQt5.QtWidgets import QApplication, QLabel

_app = QApplication.instance() or QApplication(sys.argv)

from pipeline.analysis_pipeline import AnalysisPipeline
from event_logging.admin_event_logger import AdminEventLogger
from ui.history_panel import HistoryPanel, _EVENT_ID_COLUMN
from ui.analysis_details import AnalysisDetailsDialog
from tests.fixtures.pe_builder import make_suspicious_import_pe_bytes

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# The pipeline-relevant source tree — deliberately excludes tests/,
# .venv/, and Phase 7 modules (behavior/, network/, correlation/,
# dynamic/), which are a separate, not-analyzed-file-touching subsystem
# and out of this step's scope per Step 7's own instructions.
_PIPELINE_SOURCE_DIRS = [
    "analysis", "decision", "intelligence", "pipeline", "monitor",
    "threat_intel", "ai", "event_logging", "ui", "app", "config",
]

_FORBIDDEN_EXECUTION_PATTERNS = [
    r"\bsubprocess\b",
    r"os\.system\(",
    r"os\.startfile\(",
    r"os\.exec[lv]",
    r"ShellExecute",
    r"WinExec\(",
    r"CreateProcess\(",  # the ctypes-call form; SUSPICIOUS_APIS string literals are excluded below
]


def _iter_source_files():
    for d in _PIPELINE_SOURCE_DIRS:
        base = os.path.join(_PROJECT_ROOT, d)
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            dirs[:] = [x for x in dirs if x != "__pycache__"]
            for f in files:
                if f.endswith(".py"):
                    yield os.path.join(root, f)


class TestNoExecutionInvariant:
    def test_no_execution_primitive_anywhere_in_the_pipeline_source_tree(self):
        offenders = []
        for path in _iter_source_files():
            with open(path, encoding="utf-8") as fh:
                source = fh.read()
            for lineno, line in enumerate(source.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                for pattern in _FORBIDDEN_EXECUTION_PATTERNS:
                    if re.search(pattern, line):
                        # analysis/static_analyzer.py's SUSPICIOUS_APIS list
                        # legitimately contains the strings "ShellExecuteA"/
                        # "CreateProcessA" etc. as *detection signatures* —
                        # string literals in a list, never a call. Skip a
                        # match that sits inside a string literal rather
                        # than a real function call.
                        if _is_string_literal_context(line, pattern):
                            continue
                        offenders.append(f"{path}:{lineno}: {stripped}")
        assert offenders == [], "execution primitive(s) found:\n" + "\n".join(offenders)

    def test_pipeline_never_opens_the_analyzed_file_in_a_write_mode(self):
        """Static analysis must only ever read the file, never open it for
        writing (which could truncate/modify it)."""
        path = os.path.join(_PROJECT_ROOT, "analysis", "static_analyzer.py")
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        write_mode_opens = re.findall(r'open\([^)]*["\'][wxa][b+]?["\']', source)
        assert write_mode_opens == []


def _is_string_literal_context(line: str, pattern: str) -> bool:
    match = re.search(pattern, line)
    if not match:
        return False
    before = line[:match.start()]
    # If there's an odd number of quote characters before the match on this
    # line, the match sits inside a string literal (e.g. a detection
    # signature name in SUSPICIOUS_APIS), not a real function call.
    return (before.count('"') % 2 == 1) or (before.count("'") % 2 == 1)


class TestNoAutomaticDeletionOrModification:
    def test_no_deletion_primitive_in_pipeline_source_tree(self):
        offenders = []
        deletion_patterns = [r"os\.remove\(", r"os\.unlink\(", r"shutil\.rmtree\("]
        for path in _iter_source_files():
            with open(path, encoding="utf-8") as fh:
                source = fh.read()
            for lineno, line in enumerate(source.splitlines(), 1):
                for pattern in deletion_patterns:
                    if re.search(pattern, line) and not line.strip().startswith("#"):
                        offenders.append(f"{path}:{lineno}: {line.strip()}")
        assert offenders == [], "deletion primitive(s) found:\n" + "\n".join(offenders)

    def test_analyzing_a_file_leaves_its_bytes_completely_unchanged(self, tmp_path):
        path = tmp_path / "unmodified.exe"
        original_bytes = make_suspicious_import_pe_bytes()
        path.write_bytes(original_bytes)
        original_mtime = os.path.getmtime(path)

        pipeline = AnalysisPipeline()
        event = pipeline.analyze_and_decide(str(path))

        assert event["analysis_status"] == "completed"
        assert path.read_bytes() == original_bytes
        assert os.path.getmtime(path) == original_mtime
        assert path.exists()  # not deleted


class TestUnknownIsNeverClean:
    def test_unknown_threat_intel_never_produces_a_safe_or_clean_labeled_event(self, tmp_path):
        path = tmp_path / "susp.exe"
        path.write_bytes(make_suspicious_import_pe_bytes())

        class UnknownTI:
            def get_reputation(self, file_hash):
                return {"status": "unknown"}

        pipeline = AnalysisPipeline(threat_intel_client=UnknownTI())
        event = pipeline.analyze_and_decide(str(path))

        assert event["threat_intelligence"] == {"status": "unknown"}
        # The classification is driven ONLY by local deterministic risk —
        # unknown TI must never push it toward SAFE.
        assert event["risk"]["level"] == "SUSPICIOUS"


class TestEventIdentityAcrossFullRoundTrip:
    def test_event_id_matches_from_pipeline_through_persistence_retrieval_and_ui(self, tmp_path):
        db_path = str(tmp_path / "identity.db")
        logger = AdminEventLogger(db_path=db_path)

        class FakeTI:
            def get_reputation(self, file_hash):
                return {"status": "unknown"}

        pipeline = AnalysisPipeline(threat_intel_client=FakeTI(), persistence=logger)
        path = tmp_path / "susp.exe"
        path.write_bytes(make_suspicious_import_pe_bytes())

        # 1. Pipeline
        pipeline_event = pipeline.analyze_and_decide(str(path))
        pipeline_event_id = pipeline_event["event_id"]
        assert pipeline_event_id

        # 2. Persistence (already happened inside analyze_and_decide, but
        # confirm the same id is queryable directly against the db)
        assert pipeline_event["persistence_error"] is None

        # 3. Retrieval
        retrieved = logger.get_event(pipeline_event_id)
        assert retrieved is not None
        assert retrieved["event_id"] == pipeline_event_id

        # 4. History UI
        panel = HistoryPanel(logger, poll_interval_ms=0)
        panel.refresh()
        history_ids = [panel._table.item(r, _EVENT_ID_COLUMN).text() for r in range(panel._table.rowCount())]
        assert pipeline_event_id in history_ids

        # 5. Analysis Details UI, opened via the same id
        dialog = AnalysisDetailsDialog(retrieved)
        shown_text = "\n".join(l.text() for l in dialog.findChildren(QLabel))
        assert pipeline_event_id in shown_text
