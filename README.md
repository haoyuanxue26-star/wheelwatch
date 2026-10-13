# WheelWatch

Offline integrity and install-time risk inspection for Python wheels. Reads ZIP
members; never installs the wheel, imports package code, or contacts a service.
Python 3.11+; no runtime dependencies.

**Internal consistency is not authenticity.** An attacker can change a payload
and recompute RECORD. A clean report is not a malware verdict, publisher
verification or permission to execute the package.

## Install and run

```sh
python -m pip install 'git+https://github.com/haoyuanxue26-star/wheelwatch.git@v0.1.0'
wheelwatch downloaded_package.whl
wheelwatch --fail-on warning downloaded_package.whl
```

This installs WheelWatch itself, not the wheel being inspected. There is no
claimed PyPI publication. Use a virtual environment or pipx to isolate the tool.

Output is JSON containing `ok`, `archive`, `files`, `bytes` and `findings`.
Each finding has `severity`, `code`, `path` and `message`.

- **error**: structural, integrity, quota or I/O failure; `ok` is false.
- **warning**: requires human review, not a confirmed vulnerability.
- **info**: inventory or an explicitly unverified property.

Exit `0` means the selected policy passed; exit `1` means a finding failed that
policy; exit `2` means CLI misuse. `--fail-on warning` also fails on warnings,
without changing `ok` (which describes structural/integrity acceptance only).
Counts on error may be partial. Standard output write failures are normal Python
I/O errors and are not converted into findings.

## Checks

- Require one top-level `.dist-info` tree containing RECORD, WHEEL and METADATA.
- Check every file against RECORD, except its permitted signature files. Require
  SHA-256, SHA-384 or SHA-512, unpadded URL-safe hash encoding and matching sizes.
- Reject missing/extra RECORD references, duplicate records and duplicate ZIP
  names. RECORD itself must have an empty hash and size.
- Reject traversal/absolute paths, ambiguous path components, backslashes,
  common device names, links, special entries, encrypted entries and file/directory
  conflicts. Support stored and deflated ZIP entries only.
- Read file payloads through ZIP CRC verification under byte quotas.
- Flag ASCII `import ` / `import\t` lines in top-level `.pth` files, including
  `.data/purelib` and `.data/platlib` install locations. Handle CR, LF and CRLF.
  Other `.pth` files are inventory findings. This is not a complete model of
  every Python version, encoding or installer's startup behavior.
- Flag common native-code extensions and ELF/PE/common Mach-O headers. A binary
  can be legitimate; signatures are heuristic, not exhaustive file identification.
- Report RECORD.jws / RECORD.p7s as **unverified**, never as trusted signatures.

## Library

```python
from wheelwatch import Limits, audit

report = audit("download.whl", Limits(total_bytes=32 << 20))
for finding in report.findings:
    print(finding.severity, finding.code, finding.path)
if not report.ok:
    raise SystemExit(1)
```

## Limits and scope

| CLI flag | Default |
| --- | ---: |
| `--max-archive-bytes` | 128 MiB |
| `--max-total-bytes` | 256 MiB |
| `--max-file-bytes` | 64 MiB |
| `--max-entries` | 10,000 |
| `--max-record-bytes` | 2 MiB |

All limits must be positive integers. The input file must not be concurrently
modified. ZIP central-directory parsing occurs before the entry-count check;
input size bounds that parsing but is not an exact memory quota. Use process
limits and concurrency controls when exposing inspection as a service.

WheelWatch does not extract files, emulate installers, parse all package metadata
semantics, resolve dependencies, scan source for vulnerabilities or attest to
reproducible builds. Filesystem case/Unicode collisions and malicious code that
does not match the listed indicators can escape these heuristic warnings.
Python's ZIP parser is part of the trusted computing base: keep Python patched.

## Development and releases

```sh
python -m pip install -e .
python -m unittest discover -s tests -v
python -m pip wheel --no-deps . -w dist
wheelwatch dist/wheelwatch-0.1.0-py3-none-any.whl
```

Tests generate their own wheels. Local CLI smoke verification covered a valid
wheel, same-size payload tampering, unsafe paths, and startup-code warnings,
including checking that inspected startup code did not run. CI runs tests and
builds/audits this project's wheel on Python 3.11–3.13.

For a release, update the version and changelog, run those checks, tag the commit
and attach the built wheel to the GitHub release. Include a minimal generated
fixture when reporting a false positive. See [SECURITY.md](SECURITY.md) for
vulnerability reporting. MIT licensed.
