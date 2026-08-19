"""
Minimal, dependency-free PE32 builder for tests.

Why this exists: analysis/static_analyzer.py needs a real pefile-parseable
PE to exercise import extraction, section entropy, and PE-format error
handling. We deliberately do NOT depend on any real Windows executable on
disk (not reproducible across machines, not appropriate to commit) and do
NOT download anything (no malware, no network). Instead this module packs
the minimum valid PE32 structure by hand: DOS header, PE/COFF file header,
IMAGE_OPTIONAL_HEADER32 with 16 data directories, section headers, and
(optionally) a hand-built import table (IMAGE_IMPORT_DESCRIPTOR array +
INT/IAT + hint/name entries) referenced by data directory #1.

Verified against the project's pinned `pefile==2024.8.26` and against
`analysis.static_analyzer.analyze_file()` directly during development:
- pefile.PE() parses the output with no warnings for the "valid" cases.
- DIRECTORY_ENTRY_IMPORT round-trips DLL/API names exactly as written.
- Section entropy for a section filled with deterministic_random_bytes()
  comes back > 7.5, and for a byte-padded section comes back well under it.
- Slicing a valid build to 80 bytes reliably reproduces a graceful
  pefile.PEFormatError ("File Header missing") without touching real files.

If you change this builder, rerun tests/test_static_analyzer.py — it is
the regression check that this file still produces what it claims to.
"""
import hashlib
import struct

IMAGE_BASE = 0x400000
SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200

# Section characteristics flags (subset, from the PE spec)
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

TEXT_CHARACTERISTICS = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
RDATA_CHARACTERISTICS = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ


def _align(value, alignment):
    if value % alignment == 0:
        return value
    return value + (alignment - (value % alignment))


def deterministic_random_bytes(n, seed=b"angelguard-entropy-fixture"):
    """
    A fixed, reproducible high-entropy byte stream (SHA-256 counter
    expansion) — not os.urandom(), so the exact same bytes are produced on
    every machine and every run. Used to build a section that should be
    flagged as high entropy by static_analyzer.calculate_entropy().
    """
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:n])


def build_minimal_pe(sections, imports=None):
    """
    sections: list of (name: str, data: bytes, characteristics: int)
    imports: optional {dll_name: [api_name, ...]} — appended as an extra
             ".idata" section holding a real import table, wired up via
             the Import Table data directory so pefile's
             DIRECTORY_ENTRY_IMPORT parses it normally.

    Returns raw PE32 bytes.
    """
    sections = list(sections)
    idata = None
    if imports:
        idata = _build_import_section_data(imports, sections)
        sections.append((".idata", idata["bytes"], RDATA_CHARACTERISTICS))

    num_sections = len(sections)

    dos_header_size = 64
    pe_sig_size = 4
    file_header_size = 20
    num_data_dirs = 16
    optional_header_size = 96 + num_data_dirs * 8
    section_header_size = 40 * num_sections

    headers_size = (
        dos_header_size + pe_sig_size + file_header_size
        + optional_header_size + section_header_size
    )
    size_of_headers = _align(headers_size, FILE_ALIGNMENT)

    file_cursor = size_of_headers
    rva_cursor = _align(size_of_headers, SECTION_ALIGNMENT)
    section_layout = []
    for name, data, characteristics in sections:
        raw_size = _align(len(data), FILE_ALIGNMENT)
        section_layout.append({
            "name": name,
            "data": data,
            "characteristics": characteristics,
            "virtual_size": len(data),
            "virtual_address": rva_cursor,
            "size_of_raw_data": raw_size,
            "pointer_to_raw_data": file_cursor,
        })
        file_cursor += raw_size
        rva_cursor += _align(len(data), SECTION_ALIGNMENT)

    size_of_image = _align(rva_cursor, SECTION_ALIGNMENT)

    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, dos_header_size)

    pe_sig = b"PE\x00\x00"

    entry_section = section_layout[0]
    file_header = struct.pack(
        "<HHIIIHH",
        0x014C,             # Machine: I386
        num_sections,
        0, 0, 0,             # TimeDateStamp, PointerToSymbolTable, NumberOfSymbols
        optional_header_size,
        0x0102,              # EXECUTABLE_IMAGE | 32BIT_MACHINE
    )

    optional_header = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B, 14, 0,        # Magic (PE32), linker version
        sum(s["size_of_raw_data"] for s in section_layout if s["characteristics"] & IMAGE_SCN_CNT_CODE),
        sum(s["size_of_raw_data"] for s in section_layout if not (s["characteristics"] & IMAGE_SCN_CNT_CODE)),
        0,                    # SizeOfUninitializedData
        entry_section["virtual_address"],
        entry_section["virtual_address"],
        0,                    # BaseOfData
        IMAGE_BASE,
        SECTION_ALIGNMENT, FILE_ALIGNMENT,
        6, 0, 0, 0, 6, 0,     # OS/Image/Subsystem version fields
        0,                    # Win32VersionValue
        size_of_image,
        size_of_headers,
        0,                    # CheckSum
        3,                    # Subsystem: console
        0,                    # DllCharacteristics
        0x100000, 0x1000,     # Stack reserve/commit
        0x100000, 0x1000,     # Heap reserve/commit
        0,                    # LoaderFlags
        num_data_dirs,
    )

    data_dirs = bytearray(num_data_dirs * 8)
    if idata:
        struct.pack_into("<II", data_dirs, 1 * 8, idata["import_dir_rva"], idata["import_dir_size"])

    section_headers = bytearray()
    for s in section_layout:
        name_bytes = s["name"].encode("ascii")[:8].ljust(8, b"\x00")
        section_headers += struct.pack(
            "<8sIIIIIIHHI",
            name_bytes,
            s["virtual_size"], s["virtual_address"],
            s["size_of_raw_data"], s["pointer_to_raw_data"],
            0, 0, 0, 0,
            s["characteristics"],
        )

    header_blob = (
        bytes(dos_header) + pe_sig + file_header + optional_header
        + bytes(data_dirs) + bytes(section_headers)
    ).ljust(size_of_headers, b"\x00")

    body = bytearray()
    for s in section_layout:
        body += s["data"].ljust(s["size_of_raw_data"], b"\x00")

    return bytes(header_blob) + bytes(body)


def _build_import_section_data(imports, existing_sections):
    """Lays out an IMAGE_IMPORT_DESCRIPTOR table + INT/IAT + hint/name
    entries for a section appended after `existing_sections`. RVAs are
    computed against where that appended section will land, mirroring
    build_minimal_pe's own layout math."""
    dos_header_size = 64
    pe_sig_size = 4
    file_header_size = 20
    num_data_dirs = 16
    optional_header_size = 96 + num_data_dirs * 8
    num_sections = len(existing_sections) + 1
    section_header_size = 40 * num_sections
    headers_size = (
        dos_header_size + pe_sig_size + file_header_size
        + optional_header_size + section_header_size
    )
    size_of_headers = _align(headers_size, FILE_ALIGNMENT)

    rva_cursor = _align(size_of_headers, SECTION_ALIGNMENT)
    for _, data, _ in existing_sections:
        rva_cursor += _align(len(data), SECTION_ALIGNMENT)
    section_va = rva_cursor

    dll_names = list(imports.keys())
    descriptor_table_size = (len(dll_names) + 1) * 20

    offset = descriptor_table_size
    dll_name_offsets = {}
    dll_name_blob = bytearray()
    for dll in dll_names:
        dll_name_offsets[dll] = offset + len(dll_name_blob)
        dll_name_blob += dll.encode("ascii") + b"\x00"
    offset += len(dll_name_blob)

    hint_name_blob = bytearray()
    hint_name_offsets = {}
    for dll in dll_names:
        for api in imports[dll]:
            hint_name_offsets[(dll, api)] = offset + len(hint_name_blob)
            hint_name_blob += struct.pack("<H", 0) + api.encode("ascii") + b"\x00"
            if len(hint_name_blob) % 2:
                hint_name_blob += b"\x00"
    offset += len(hint_name_blob)

    int_offsets = {}
    int_blob = bytearray()
    for dll in dll_names:
        int_offsets[dll] = offset + len(int_blob)
        for api in imports[dll]:
            int_blob += struct.pack("<I", section_va + hint_name_offsets[(dll, api)])
        int_blob += struct.pack("<I", 0)
    offset += len(int_blob)

    iat_offsets = {}
    iat_blob = bytearray()
    for dll in dll_names:
        iat_offsets[dll] = offset + len(iat_blob)
        for api in imports[dll]:
            iat_blob += struct.pack("<I", section_va + hint_name_offsets[(dll, api)])
        iat_blob += struct.pack("<I", 0)

    descriptor_blob = bytearray()
    for dll in dll_names:
        descriptor_blob += struct.pack(
            "<IIIII",
            section_va + int_offsets[dll],
            0, 0,
            section_va + dll_name_offsets[dll],
            section_va + iat_offsets[dll],
        )
    descriptor_blob += b"\x00" * 20

    full = bytes(descriptor_blob) + bytes(dll_name_blob) + bytes(hint_name_blob) + bytes(int_blob) + bytes(iat_blob)
    return {
        "bytes": full,
        "import_dir_rva": section_va,
        "import_dir_size": descriptor_table_size,
    }


# ---------------------------------------------------------------------------
# Convenience fixtures used directly by tests/test_static_analyzer.py
# ---------------------------------------------------------------------------

def make_valid_pe_bytes():
    """One .text section of low-entropy padding, no imports."""
    return build_minimal_pe([(".text", b"\x90" * 256, TEXT_CHARACTERISTICS)])


def make_suspicious_import_pe_bytes():
    """Imports two APIs on static_analyzer.SUSPICIOUS_APIS and one that
    is not, so tests can assert exact filtering behavior."""
    return build_minimal_pe(
        [(".text", b"\x90" * 64, TEXT_CHARACTERISTICS)],
        imports={"KERNEL32.dll": ["VirtualAlloc", "CreateRemoteThread", "ExitProcess"]},
    )


def make_high_entropy_pe_bytes():
    """A second section filled with deterministic high-entropy bytes
    alongside a normal low-entropy .text section, so tests can assert
    both the flagged and unflagged section report correctly."""
    return build_minimal_pe([
        (".text", b"\x90" * 64, TEXT_CHARACTERISTICS),
        (".rdata", deterministic_random_bytes(4096), RDATA_CHARACTERISTICS),
    ])


def make_truncated_pe_bytes():
    """A valid build sliced to 80 bytes — cuts off right after the PE/COFF
    file header, before the optional header. Verified to reliably produce
    pefile.PEFormatError('File Header missing') rather than a silent
    partial parse."""
    return make_valid_pe_bytes()[:80]
