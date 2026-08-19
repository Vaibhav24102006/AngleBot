"""
Regression suite for analysis/static_analyzer.py.

Locks in the module's actual current behavior (not the original vision
doc's aspirational feature list). Every fixture is generated in-process by
tests/fixtures/pe_builder.py — no real executables, no network, no
dependency on any specific machine's filesystem.
"""
import hashlib
import struct
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analysis.static_analyzer import analyze_file, get_analysis_summary, calculate_entropy
from tests.fixtures.pe_builder import (
    build_minimal_pe,
    make_valid_pe_bytes,
    make_suspicious_import_pe_bytes,
    make_high_entropy_pe_bytes,
    make_truncated_pe_bytes,
    deterministic_random_bytes,
    TEXT_CHARACTERISTICS,
)


def _write(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


# --------------------------------------------------------------------------- #
# Valid PE
# --------------------------------------------------------------------------- #

class TestValidPE:
    def test_analysis_succeeds_with_no_error(self, tmp_path):
        data = make_valid_pe_bytes()
        result = analyze_file(_write(tmp_path, "valid.exe", data))
        assert result["error"] is None

    def test_sha256_matches_independently_computed_hash(self, tmp_path):
        data = make_valid_pe_bytes()
        result = analyze_file(_write(tmp_path, "valid.exe", data))
        assert result["hash"] == hashlib.sha256(data).hexdigest()

    def test_file_size_matches_fixture_size(self, tmp_path):
        data = make_valid_pe_bytes()
        result = analyze_file(_write(tmp_path, "valid.exe", data))
        assert result["file_size"] == len(data)

    def test_pe_parsing_succeeds_and_sections_are_extracted(self, tmp_path):
        data = make_valid_pe_bytes()
        result = analyze_file(_write(tmp_path, "valid.exe", data))
        assert result["num_sections"] == 1
        assert result["sections"][0]["name"] == ".text"
        assert result["sections"][0]["size"] > 0

    def test_entropy_is_reported_per_section(self, tmp_path):
        data = make_valid_pe_bytes()
        result = analyze_file(_write(tmp_path, "valid.exe", data))
        assert isinstance(result["sections"][0]["entropy"], float)
        assert result["high_entropy_sections"] == 0  # 0x90 padding -> low entropy

    def test_no_imports_means_zero_counts(self, tmp_path):
        data = make_valid_pe_bytes()
        result = analyze_file(_write(tmp_path, "valid.exe", data))
        assert result["total_imports"] == 0
        assert result["num_suspicious_imports"] == 0
        assert result["suspicious_imports"] == []

    def test_string_extraction_runs_and_returns_a_count(self, tmp_path):
        data = make_valid_pe_bytes()
        result = analyze_file(_write(tmp_path, "valid.exe", data))
        assert isinstance(result["total_strings"], int)
        assert result["total_strings"] >= 0


# --------------------------------------------------------------------------- #
# Non-PE input
# --------------------------------------------------------------------------- #

class TestNonPE:
    def test_plain_text_does_not_raise_and_is_flagged_invalid(self, tmp_path):
        path = tmp_path / "not_a_pe.txt"
        path.write_bytes(b"This is not a PE file, just plain text.\n" * 5)
        result = analyze_file(str(path))  # must not raise
        assert result["error"] == "Not a valid PE file"

    def test_plain_text_still_reports_hash_and_size(self, tmp_path):
        data = b"plain text content used for hashing\n"
        path = tmp_path / "not_a_pe.txt"
        path.write_bytes(data)
        result = analyze_file(str(path))
        assert result["hash"] == hashlib.sha256(data).hexdigest()
        assert result["file_size"] == len(data)


# --------------------------------------------------------------------------- #
# Empty file
# --------------------------------------------------------------------------- #

class TestEmptyFile:
    def test_empty_file_does_not_raise_and_is_flagged_invalid(self, tmp_path):
        path = tmp_path / "empty.exe"
        path.write_bytes(b"")
        result = analyze_file(str(path))  # must not raise
        # static_analyzer routes empty files through pefile's own
        # PEFormatError("The file is empty"), which is caught and mapped to
        # the same "Not a valid PE file" error as any other malformed PE —
        # there is no separate empty-file branch in this module.
        assert result["error"] == "Not a valid PE file"
        assert result["file_size"] == 0

    def test_empty_file_hash_is_sha256_of_empty_bytes(self, tmp_path):
        path = tmp_path / "empty.exe"
        path.write_bytes(b"")
        result = analyze_file(str(path))
        assert result["hash"] == hashlib.sha256(b"").hexdigest()


# --------------------------------------------------------------------------- #
# Malformed / truncated PE
# --------------------------------------------------------------------------- #

class TestMalformedPE:
    def test_truncated_pe_does_not_raise_and_is_flagged_invalid(self, tmp_path):
        data = make_truncated_pe_bytes()
        result = analyze_file(_write(tmp_path, "truncated.exe", data))
        assert result["error"] == "Not a valid PE file"

    def test_truncated_pe_still_reports_size_and_hash(self, tmp_path):
        data = make_truncated_pe_bytes()
        result = analyze_file(_write(tmp_path, "truncated.exe", data))
        assert result["file_size"] == len(data)
        assert result["hash"] == hashlib.sha256(data).hexdigest()

    def test_bad_pe_signature_does_not_raise_and_is_flagged_invalid(self, tmp_path):
        # Valid MZ header + e_lfanew pointing at 4 bytes that are not 'PE\0\0'.
        data = bytearray(128)
        data[0:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 64)
        data[64:68] = b"XXXX"
        result = analyze_file(_write(tmp_path, "badsig.exe", bytes(data)))
        assert result["error"] == "Not a valid PE file"

    def test_nonexistent_file_does_not_raise(self, tmp_path):
        missing = str(tmp_path / "does_not_exist.exe")
        result = analyze_file(missing)  # must not raise
        assert result["error"] is not None


# --------------------------------------------------------------------------- #
# Suspicious imports
# --------------------------------------------------------------------------- #

class TestSuspiciousImports:
    def test_known_suspicious_apis_are_flagged(self, tmp_path):
        data = make_suspicious_import_pe_bytes()
        result = analyze_file(_write(tmp_path, "susp.exe", data))
        assert result["num_suspicious_imports"] == 2
        assert "KERNEL32.dll:VirtualAlloc" in result["suspicious_imports"]
        assert "KERNEL32.dll:CreateRemoteThread" in result["suspicious_imports"]

    def test_non_suspicious_import_is_not_flagged(self, tmp_path):
        data = make_suspicious_import_pe_bytes()
        result = analyze_file(_write(tmp_path, "susp.exe", data))
        assert not any("ExitProcess" in imp for imp in result["suspicious_imports"])

    def test_total_imports_counts_every_api_not_just_suspicious_ones(self, tmp_path):
        data = make_suspicious_import_pe_bytes()  # VirtualAlloc, CreateRemoteThread, ExitProcess
        result = analyze_file(_write(tmp_path, "susp.exe", data))
        assert result["total_imports"] == 3

    def test_suspicious_api_matching_is_case_insensitive(self, tmp_path):
        # static_analyzer.py compares suspicious_api.lower() == api_name.lower()
        data = build_minimal_pe(
            [(".text", b"\x90" * 64, TEXT_CHARACTERISTICS)],
            imports={"KERNEL32.dll": ["virtualalloc"]},
        )
        result = analyze_file(_write(tmp_path, "caseinsensitive.exe", data))
        assert result["num_suspicious_imports"] == 1

    def test_no_suspicious_imports_present_gives_empty_list(self, tmp_path):
        data = build_minimal_pe(
            [(".text", b"\x90" * 64, TEXT_CHARACTERISTICS)],
            imports={"KERNEL32.dll": ["ExitProcess", "GetModuleHandleA"]},
        )
        result = analyze_file(_write(tmp_path, "benign_imports.exe", data))
        assert result["num_suspicious_imports"] == 0
        assert result["suspicious_imports"] == []
        assert result["total_imports"] == 2


# --------------------------------------------------------------------------- #
# High entropy
# --------------------------------------------------------------------------- #

class TestHighEntropy:
    def test_high_entropy_section_is_flagged(self, tmp_path):
        data = make_high_entropy_pe_bytes()
        result = analyze_file(_write(tmp_path, "hi_entropy.exe", data))
        assert result["high_entropy_sections"] == 1
        rdata = next(s for s in result["sections"] if s["name"] == ".rdata")
        assert rdata["entropy"] > 7.5

    def test_low_entropy_section_in_same_file_is_not_flagged(self, tmp_path):
        data = make_high_entropy_pe_bytes()
        result = analyze_file(_write(tmp_path, "hi_entropy.exe", data))
        text = next(s for s in result["sections"] if s["name"] == ".text")
        assert text["entropy"] < 7.5

    def test_calculate_entropy_all_zero_bytes_is_zero(self):
        assert calculate_entropy(b"\x00" * 1000) == 0.0

    def test_calculate_entropy_deterministic_random_bytes_is_high(self):
        assert calculate_entropy(deterministic_random_bytes(4096)) > 7.5

    def test_calculate_entropy_empty_input_is_zero(self):
        assert calculate_entropy(b"") == 0.0


# --------------------------------------------------------------------------- #
# Hashing / file size
# --------------------------------------------------------------------------- #

class TestHashingAndSize:
    def test_different_content_produces_different_hash(self, tmp_path):
        data_a = make_valid_pe_bytes()
        data_b = make_suspicious_import_pe_bytes()
        result_a = analyze_file(_write(tmp_path, "a.exe", data_a))
        result_b = analyze_file(_write(tmp_path, "b.exe", data_b))
        assert result_a["hash"] != result_b["hash"]

    def test_file_size_reflects_actual_bytes_on_disk(self, tmp_path):
        data = make_high_entropy_pe_bytes()
        path = _write(tmp_path, "sized.exe", data)
        result = analyze_file(path)
        assert result["file_size"] == len(data) == os.path.getsize(path)


# --------------------------------------------------------------------------- #
# Reproducibility
# --------------------------------------------------------------------------- #

class TestReproducibility:
    def test_analyzing_the_same_fixture_twice_is_equivalent(self, tmp_path):
        data = make_suspicious_import_pe_bytes()
        path = _write(tmp_path, "susp.exe", data)
        result_1 = analyze_file(path)
        result_2 = analyze_file(path)
        # analyze_file()'s output has no timestamps or other dynamic fields,
        # so re-analyzing the same bytes must be exactly equal.
        assert result_1 == result_2


# --------------------------------------------------------------------------- #
# get_analysis_summary — the module's other public function
# --------------------------------------------------------------------------- #

class TestAnalysisSummary:
    def test_summary_reports_error_for_invalid_pe(self, tmp_path):
        data = make_truncated_pe_bytes()
        result = analyze_file(_write(tmp_path, "truncated.exe", data))
        summary = get_analysis_summary(result)
        assert "Error" in summary
        assert "Not a valid PE file" in summary

    def test_summary_includes_hash_and_imports_for_valid_pe(self, tmp_path):
        data = make_suspicious_import_pe_bytes()
        result = analyze_file(_write(tmp_path, "susp.exe", data))
        summary = get_analysis_summary(result)
        assert result["hash"] in summary
        assert "KERNEL32.dll:VirtualAlloc" in summary
