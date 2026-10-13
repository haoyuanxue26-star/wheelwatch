import base64
import csv
import hashlib
import io
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

from wheelwatch import Limits, audit


ROOT = "example-1.0.dist-info"


def make_wheel(path, extra=None, mutate_rows=None, mutate_files=None):
    files = {
        "example/__init__.py": b"answer = 42\n",
        ROOT + "/WHEEL": b"Wheel-Version: 1.0\nGenerator: tests\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        ROOT + "/METADATA": b"Metadata-Version: 2.1\nName: example\nVersion: 1.0\n",
        **(extra or {}),
    }
    rows = [[name, "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode(), str(len(body))] for name, body in files.items()]
    rows.append([ROOT + "/RECORD", "", ""])
    if mutate_rows:
        mutate_rows(rows)
    record = io.StringIO(newline="")
    csv.writer(record).writerows(rows)
    files[ROOT + "/RECORD"] = record.getvalue().encode()
    if mutate_files:
        mutate_files(files)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as wheel:
        for name, body in files.items():
            wheel.writestr(name, body)
    return path


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "example-1.0-py3-none-any.whl"

    def codes(self, **kwargs):
        return {f.code for f in audit(self.path, **kwargs).findings}

    def test_valid_wheel(self):
        make_wheel(self.path)
        report = audit(self.path)
        self.assertTrue(report.ok, report.findings)
        self.assertEqual(report.findings, [])
        self.assertEqual(report.files, 4)

    def test_modified_payload(self):
        make_wheel(self.path, mutate_files=lambda files: files.update({"example/__init__.py": b"answer = 43\n"}))
        self.assertIn("HASH_MISMATCH", self.codes())
        self.assertFalse(audit(self.path).ok)

    def test_missing_and_extra_records(self):
        make_wheel(self.path, mutate_rows=lambda rows: rows.pop(0))
        self.assertIn("RECORD_MISSING", self.codes())
        make_wheel(self.path, mutate_files=lambda files: files.pop("example/__init__.py"))
        self.assertIn("RECORD_EXTRA", self.codes())

    def test_bad_hash_size_self_and_duplicate(self):
        mutations = [
            (lambda rows: rows[0].__setitem__(1, "md5=abcd"), "HASH_UNSUPPORTED"),
            (lambda rows: rows[0].__setitem__(1, "sha256=@@@@"), "HASH_ENCODING"),
            (lambda rows: rows[0].__setitem__(2, "999"), "SIZE_MISMATCH"),
            (lambda rows: rows[0].__setitem__(2, "-1"), "SIZE_INVALID"),
            (lambda rows: rows[-1].__setitem__(2, "0"), "RECORD_SELF"),
            (lambda rows: rows.append(rows[0]), "INVALID_WHEEL"),
        ]
        for mutation, expected in mutations:
            with self.subTest(expected=expected):
                make_wheel(self.path, mutate_rows=mutation)
                self.assertIn(expected, self.codes())

    def test_startup_code_and_native_are_warnings(self):
        for body in (b"import os\n", b"# comment\rimport\tos\r", b"#" * 65532 + b"\nimport os\n"):
            with self.subTest(body_length=len(body)):
                make_wheel(self.path, {"startup.pth": body, "lib/native.so": b"\x7fELFcontent"})
                report = audit(self.path)
                self.assertTrue(report.ok)
                self.assertEqual({f.code for f in report.findings}, {"PTH_STARTUP_CODE", "NATIVE_BINARY"})
        make_wheel(self.path, {"example/nested.pth": b"import os\n"})
        self.assertEqual(self.codes(), {"PTH_FILE"})
        make_wheel(self.path, {"example-1.0.data/purelib/startup.pth": b"import os\n"})
        self.assertEqual(self.codes(), {"PTH_STARTUP_CODE"})

    def test_unsafe_names_and_conflicts(self):
        for extra in ({"../escape": b"x"}, {"/absolute": b"x"}, {"C:\\escape": b"x"}, {"p": b"x", "p/a": b"y"}):
            with self.subTest(extra=extra):
                make_wheel(self.path, extra)
                self.assertFalse(audit(self.path).ok)

    def test_symlink_and_duplicate_zip(self):
        make_wheel(self.path)
        with zipfile.ZipFile(self.path, "a") as wheel:
            info = zipfile.ZipInfo("link")
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            wheel.writestr(info, "../target")
        self.assertIn("INVALID_WHEEL", self.codes())
        make_wheel(self.path)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.path, "a") as wheel:
                wheel.writestr("example/__init__.py", b"duplicate")
        self.assertFalse(audit(self.path).ok)

    def test_limits_and_truncation(self):
        make_wheel(self.path)
        for limits in (Limits(entries=1), Limits(file_bytes=1), Limits(total_bytes=1), Limits(archive_bytes=1), Limits(record_bytes=1), Limits(entries=0)):
            self.assertFalse(audit(self.path, limits).ok)
        self.path.write_bytes(self.path.read_bytes()[:-30])
        self.assertFalse(audit(self.path).ok)

    def test_signature_is_not_authentication(self):
        make_wheel(self.path, mutate_files=lambda files: files.update({ROOT + "/RECORD.jws": b"unverified"}))
        self.assertTrue(audit(self.path).ok)
        self.assertEqual(self.codes(), {"SIGNATURE_UNVERIFIED"})


if __name__ == "__main__":
    unittest.main()
