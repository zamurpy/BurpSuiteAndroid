# Author: ZamurSec | https://discord.com/invite/AA92kB5GSB
# (c) 2026 ZamurSec - All Rights Reserved. See LICENSE. Do not redistribute/modify without permission.

"""
httputil.py - Bantuan parsing & decoding body HTTP:
- dechunk Transfer-Encoding: chunked
- decompress Content-Encoding: gzip / deflate / br
- deteksi charset dari Content-Type (banyak situs lama/legacy ASP.NET
  gak pakai UTF-8, misal testaspnet.vulnweb.com pakai Windows-1252/ISO-8859-1.
  Maksa decode UTF-8 di situs begini bikin teks nya berantakan/acak-acak)
Supaya History & Repeater nampilin HTML asli, bukan bytes mentah/rusak.
"""
import gzip
import re
import zlib

try:
    import brotli
    HAVE_BROTLI = True
except ImportError:
    HAVE_BROTLI = False

# Karakter kontrol Unicode bidi (RTL override dsb) - kalau nyelip gara-gara
# decoding yang gak pas, bikin teks kebalik-balik di layar. Buang aja,
# gak ada gunanya buat nampilin raw HTTP/HTML.
_BIDI_CONTROL_RE = re.compile(
    "[\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069]"
)

_CHARSET_RE = re.compile(rb"charset=([a-zA-Z0-9_\-]+)", re.IGNORECASE)


def dechunk(data: bytes) -> bytes:
    """Ubah body chunked-encoded jadi body biasa."""
    result = b""
    while data:
        idx = data.find(b"\r\n")
        if idx == -1:
            break
        size_line = data[:idx].split(b";")[0].strip()
        try:
            size = int(size_line, 16)
        except ValueError:
            break
        if size == 0:
            break
        chunk_data = data[idx + 2: idx + 2 + size]
        result += chunk_data
        data = data[idx + 2 + size + 2:]  # lewati \r\n penutup chunk
    return result


def decompress(body: bytes, content_encoding: str) -> bytes:
    enc = (content_encoding or "").lower()
    try:
        if "gzip" in enc:
            return gzip.decompress(body)
        if "deflate" in enc:
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
        if "br" in enc:
            if HAVE_BROTLI:
                return brotli.decompress(body)
            return body  # module brotli gak ada, biarkan apa adanya
    except Exception:
        return body
    return body


def _detect_charset(headers: dict) -> str:
    """Cari charset dari header Content-Type, mis: 'text/html; charset=iso-8859-1'."""
    content_type = headers.get("Content-Type", headers.get("content-type", ""))
    m = _CHARSET_RE.search(content_type.encode(errors="ignore"))
    if m:
        return m.group(1).decode(errors="ignore").lower()
    return ""


def decode_body_bytes(body: bytes, headers: dict = None) -> str:
    """Decode bytes -> text, coba charset dari header dulu, baru fallback bertingkat.
    Banyak situs lama (ASP.NET classic dsb) pakai Windows-1252/ISO-8859-1, bukan UTF-8.
    Maksa UTF-8 di situs begini bikin teks acak-acak/mojibake."""
    headers = headers or {}
    charset = _detect_charset(headers)

    candidates = []
    if charset:
        candidates.append(charset)
    candidates += ["utf-8", "cp1252", "iso-8859-1"]

    for enc in candidates:
        try:
            text = body.decode(enc)
            return _BIDI_CONTROL_RE.sub("", text)
        except (UnicodeDecodeError, LookupError):
            continue

    # fallback terakhir: cp1252 gak pernah gagal (semua byte 0-255 valid di situ)
    text = body.decode("cp1252", errors="replace")
    return _BIDI_CONTROL_RE.sub("", text)


def decode_response_body(headers: dict, body: bytes) -> str:
    """headers: dict header response (case-sensitive key seperti aslinya).
    Return string body yang sudah di-dechunk, di-decompress, dan di-decode
    pakai charset yang tepat."""
    transfer_enc = headers.get("Transfer-Encoding", headers.get("transfer-encoding", ""))
    content_enc = headers.get("Content-Encoding", headers.get("content-encoding", ""))

    if "chunked" in transfer_enc.lower():
        body = dechunk(body)
    if content_enc:
        body = decompress(body, content_enc)

    return decode_body_bytes(body, headers)


def parse_raw_response(data: bytes):
    """Pecah raw response bytes -> (headers_text, headers_dict, body_bytes)."""
    idx = data.find(b"\r\n\r\n")
    if idx == -1:
        return data.decode(errors="replace"), {}, b""
    head = data[:idx]
    body = data[idx + 4:]
    headers_text = head.decode(errors="replace")
    headers = {}
    for line in headers_text.split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers_text, headers, body
