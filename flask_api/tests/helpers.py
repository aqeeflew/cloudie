"""Shared helpers for the Flask tests (stdlib unittest, no extra dependencies)."""

import os
import sys
import tempfile

# Make `import app`, `import verdict_engine`, ... work when running from flask_api/
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Never write the prediction log into the real project folder during tests
os.environ.setdefault("PREDICTION_LOG_PATH",
                      os.path.join(tempfile.gettempdir(), "cloudie_test_prediction_log.csv"))

# A tiny, harmless PDF with no risky content
PDF_PLAIN = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>
endobj
trailer
<< /Root 1 0 R >>
%%EOF
"""

# A tiny, harmless PDF with /OpenAction + /JavaScript (app.alert only)
PDF_JS = b"""%PDF-1.3
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>
endobj
4 0 obj
<< /Type /Action /S /JavaScript /JS (app.alert\\('Cloudie test - harmless'\\);) >>
endobj
trailer
<< /Root 1 0 R >>
%%EOF
"""

def _png_chunk(ctype: bytes, data: bytes) -> bytes:
    import struct
    import zlib
    return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", zlib.crc32(ctype + data) & 0xffffffff)


def _make_png() -> bytes:
    """A real, valid 1x1 PNG (signature + IHDR + IDAT + IEND): not a PDF, and nothing hidden in it."""
    import struct
    import zlib
    return (b"\x89PNG\r\n\x1a\n"
            + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + _png_chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00"))
            + _png_chunk(b"IEND", b""))


PNG_BYTES = _make_png()


def write_temp(data: bytes, suffix: str = ".pdf") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path
