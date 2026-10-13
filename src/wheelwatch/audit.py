"""Structural and RECORD integrity checks for wheel ZIP containers."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import re
import stat
import zipfile
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Limits:
    archive_bytes: int = 128 << 20
    total_bytes: int = 256 << 20
    file_bytes: int = 64 << 20
    entries: int = 10_000
    record_bytes: int = 2 << 20


@dataclass(frozen=True)
class Finding:
    severity: str  # error: rejected; warning: review required; info: inventory
    code: str
    path: str
    message: str


@dataclass
class Report:
    archive: str
    files: int = 0
    bytes: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(f.severity == "error" for f in self.findings)

    def to_dict(self) -> dict:
        return {"ok": self.ok, **asdict(self)}


class Rejected(ValueError):
    pass


def _safe_path(name: str) -> bool:
    if not name or len(name) > 4096 or name.startswith("/") or any(c in name for c in "\\:\x00"):
        return False
    for part in name.removesuffix("/").split("/"):
        if part in ("", ".", "..") or part.rstrip(" .") != part:
            return False
        if any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in part):
            return False
        if re.fullmatch(r"CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9]", part.split(".")[0], re.I):
            return False
    return True


def _startup_location(name: str) -> bool:
    parts = name.split("/")
    return len(parts) == 1 or (
        len(parts) == 3 and parts[0].endswith(".data") and parts[1] in ("purelib", "platlib")
    )


def audit(source: str | Path, limits: Limits = Limits()) -> Report:
    """Read a wheel under limits; return findings, including input/I/O errors.

    RECORD hashes establish internal consistency, not publisher authenticity.
    The input must not be concurrently modified. The function does not extract.
    """
    report = Report(str(source))

    def add(severity: str, code: str, path: str, message: str) -> None:
        report.findings.append(Finding(severity, code, path, message))

    try:
        if any(type(v) is not int or v <= 0 for v in asdict(limits).values()):
            raise Rejected("all limits must be positive integers")
        source = Path(source)
        if source.suffix.lower() != ".whl":
            raise Rejected("input must have a .whl extension")
        with source.open("rb") as raw:
            import os
            st = os.fstat(raw.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_size > limits.archive_bytes:
                raise Rejected("input is not a regular file within the archive byte limit")
            with zipfile.ZipFile(raw) as wheel:
                infos = wheel.infolist()
                if len(infos) > limits.entries:
                    raise Rejected("entry count limit exceeded")
                by_name: dict[str, zipfile.ZipInfo] = {}
                required_dirs: set[str] = set()
                normalized: dict[str, bool] = {}
                total = 0
                for entry in infos:
                    # orig_filename preserves NUL suffixes stripped by zipfile.
                    name = entry.orig_filename
                    if not _safe_path(name):
                        raise Rejected(f"unsafe archive path: {name!r}")
                    key = name.removesuffix("/")
                    if key in normalized:
                        raise Rejected(f"duplicate archive path: {name!r}")
                    directory = entry.is_dir()
                    if entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                        raise Rejected(f"unsupported compression method: {name!r}")
                    mode = entry.external_attr >> 16
                    kind = stat.S_IFMT(mode)
                    if kind not in (0, stat.S_IFREG, stat.S_IFDIR) or (kind == stat.S_IFDIR and not directory) or (kind == stat.S_IFREG and directory):
                        raise Rejected(f"link, special file or inconsistent file type: {name!r}")
                    if entry.flag_bits & 1:
                        raise Rejected(f"encrypted entry: {name!r}")
                    parts = key.split("/")
                    for i in range(1, len(parts)):
                        parent = "/".join(parts[:i])
                        if normalized.get(parent) is False:
                            raise Rejected(f"parent is a file: {name!r}")
                        required_dirs.add(parent)
                    if not directory and key in required_dirs:
                        raise Rejected(f"file/directory conflict: {name!r}")
                    normalized[key] = directory
                    if entry.file_size > limits.file_bytes or (directory and entry.file_size):
                        raise Rejected(f"entry size limit or directory payload: {name!r}")
                    total += entry.file_size
                    if total > limits.total_bytes:
                        raise Rejected("total payload limit exceeded")
                    if not directory:
                        by_name[name] = entry
                roots = {n.split("/")[0] for n in by_name if n.split("/")[0].endswith(".dist-info")}
                if len(roots) != 1:
                    raise Rejected("expected exactly one top-level .dist-info directory")
                root = roots.pop()
                record_name = root + "/RECORD"
                for required in (record_name, root + "/WHEEL", root + "/METADATA"):
                    if required not in by_name:
                        raise Rejected(f"missing wheel metadata: {required}")
                if by_name[record_name].file_size > limits.record_bytes:
                    raise Rejected("RECORD byte limit exceeded")
                record = wheel.read(by_name[record_name]).decode("utf-8")
                records: dict[str, tuple[str, str]] = {}
                for row in csv.reader(io.StringIO(record, newline=""), strict=True):
                    if len(row) != 3 or not _safe_path(row[0]) or row[0].endswith("/"):
                        raise Rejected("malformed RECORD row or unsafe RECORD path")
                    if row[0] in records:
                        raise Rejected(f"duplicate RECORD row: {row[0]!r}")
                    records[row[0]] = (row[1], row[2])
                signatures = {root + "/RECORD.jws", root + "/RECORD.p7s"}
                for name in records.keys() - by_name.keys():
                    add("error", "RECORD_EXTRA", name, "RECORD references an absent file")
                for name in sorted(by_name):
                    entry = by_name[name]
                    spec = records.get(name)
                    digest = None
                    expected = None
                    if name in signatures:
                        add("info", "SIGNATURE_UNVERIFIED", name, "Signature present; authenticity is not verified")
                        if spec is not None:
                            add("error", "SIGNATURE_IN_RECORD", name, "Wheel signature files must not be listed in RECORD")
                    elif spec is None:
                        add("error", "RECORD_MISSING", name, "File is absent from RECORD")
                    elif name == record_name:
                        if spec != ("", ""):
                            add("error", "RECORD_SELF", name, "RECORD's own hash and size must be empty")
                    else:
                        algorithm, sep, encoded = spec[0].partition("=")
                        if not sep or algorithm not in ("sha256", "sha384", "sha512"):
                            add("error", "HASH_UNSUPPORTED", name, "Require SHA-256, SHA-384 or SHA-512")
                        else:
                            try:
                                expected = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
                                digest = hashlib.new(algorithm)
                                canonical = base64.urlsafe_b64encode(expected).rstrip(b"=").decode("ascii")
                                if canonical != encoded or len(expected) != digest.digest_size:
                                    raise ValueError("noncanonical hash")
                            except ValueError:
                                add("error", "HASH_ENCODING", name, "Invalid unpadded URL-safe hash encoding")
                                digest = None
                        if not re.fullmatch(r"[0-9]+", spec[1]) or len(spec[1]) > 20:
                            add("error", "SIZE_INVALID", name, "RECORD size must be a decimal integer")
                        elif int(spec[1]) != entry.file_size:
                            add("error", "SIZE_MISMATCH", name, "RECORD size differs from the ZIP entry")
                    count = 0
                    prefix = b""
                    line_prefix = b""
                    pth_import = False
                    is_pth = name.endswith(".pth")
                    with wheel.open(entry) as payload:
                        while chunk := payload.read(65536):
                            count += len(chunk)
                            if count > limits.file_bytes or report.bytes + count > limits.total_bytes:
                                raise Rejected("actual payload byte limit exceeded")
                            if len(prefix) < 4:
                                prefix = (prefix + chunk)[:4]
                            if digest is not None:
                                digest.update(chunk)
                            if is_pth:
                                segments = chunk.replace(b"\r", b"\n").split(b"\n")
                                for index, segment in enumerate(segments):
                                    line_prefix = (line_prefix + segment[:7])[:7]
                                    if line_prefix.startswith((b"import ", b"import\t")):
                                        pth_import = True
                                    if index < len(segments) - 1:
                                        line_prefix = b""
                    if count != entry.file_size:
                        add("error", "ACTUAL_SIZE", name, "Decoded size differs from metadata")
                    if digest is not None and digest.digest() != expected:
                        add("error", "HASH_MISMATCH", name, "File content does not match RECORD hash")
                    if is_pth:
                        if pth_import and _startup_location(name):
                            add("warning", "PTH_STARTUP_CODE", name, "Import line may execute when Python initializes site-packages")
                        else:
                            add("info", "PTH_FILE", name, "Path configuration file; review install location and contents")
                    if prefix in (b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe") or prefix[:2] == b"MZ" or name.lower().endswith((".so", ".pyd", ".dll", ".dylib")):
                        add("warning", "NATIVE_BINARY", name, "Native code requires separate review; this is not a malware verdict")
                    report.files += 1
                    report.bytes += count
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError, NotImplementedError, csv.Error, EOFError, zlib.error) as exc:
        add("error", "INVALID_WHEEL", str(source), str(exc))
    return report
