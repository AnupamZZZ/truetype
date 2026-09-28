import struct
from truetype import analyze, verdict

PE = b"MZ" + b"\0" * 58 + struct.pack("<I", 0x80) + b"\0" * 64 + b"PE\0\0" + b"\0" * 200
PNG = b"\x89PNG\r\n\x1a\n" + b"\0" * 20 + b"IEND\xaeB`\x82"


def scan(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return verdict(analyze(str(p))["findings"])


def test_genuine_png_is_clean(tmp_path):
    assert scan(tmp_path, "ok.png", PNG) == "CLEAN"


def test_exe_renamed_to_png(tmp_path):
    assert scan(tmp_path, "fake.png", PE) == "DANGEROUS"


def test_exe_renamed_to_mp4(tmp_path):
    assert scan(tmp_path, "movie.mp4", PE) == "DANGEROUS"


def test_real_exe_with_exe_extension_not_flagged_as_disguised(tmp_path):
    assert scan(tmp_path, "setup.exe", PE) == "CLEAN"


def test_double_extension(tmp_path):
    assert scan(tmp_path, "invoice.pdf.exe", PE) == "DANGEROUS"


def test_payload_appended_to_png(tmp_path):
    assert scan(tmp_path, "hidden.png", PNG + b"A" * 50 + PE) == "DANGEROUS"


def test_bidi_override_filename(tmp_path):
    assert scan(tmp_path, "photo\u202egnp.exe", PE) == "DANGEROUS"


def test_fake_video_without_signature_is_suspicious(tmp_path):
    assert scan(tmp_path, "movie.mp4", b"just text, not a video") == "SUSPICIOUS"


ELF = b"\x7fELF\x02\x01\x01" + b"\0" * 100


def test_program_without_extension_is_only_a_warning(tmp_path):
    assert scan(tmp_path, "myprogram", ELF) == "SUSPICIOUS"


def test_shared_library_is_not_flagged(tmp_path):
    assert scan(tmp_path, "lib.so", ELF) == "CLEAN"


def test_java_class_file_is_not_flagged(tmp_path):
    assert scan(tmp_path, "Hello.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x3d" + b"\0" * 50) == "CLEAN"


def test_python_script_with_shebang_is_fine(tmp_path):
    assert scan(tmp_path, "tool.py", b"#!/usr/bin/env python3\nprint(1)\n") == "CLEAN"


def test_script_disguised_as_image_still_flagged(tmp_path):
    assert scan(tmp_path, "cute.png", b"#!/bin/bash\necho hi\n") == "DANGEROUS"


def test_elf_disguised_as_video(tmp_path):
    assert scan(tmp_path, "movie.mp4", ELF) == "DANGEROUS"
