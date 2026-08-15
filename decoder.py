# Author: ZamurSec | https://discord.com/invite/AA92kB5GSB
# (c) 2026 ZamurSec - All Rights Reserved. See LICENSE. Do not redistribute/modify without permission.

"""
decoder.py - URL / Base64 / Hex encode-decode, mirip tab Decoder di Burp.
"""
import base64
import urllib.parse
import binascii


def url_decode(s):
    return urllib.parse.unquote(s)


def url_encode(s):
    return urllib.parse.quote(s, safe="")


def b64_decode(s):
    try:
        padded = s + "=" * (-len(s) % 4)
        return base64.b64decode(padded).decode(errors="replace")
    except Exception as e:
        return f"[error] {e}"


def b64_encode(s):
    return base64.b64encode(s.encode()).decode()


def hex_decode(s):
    try:
        clean = s.replace(" ", "").replace("0x", "")
        return bytes.fromhex(clean).decode(errors="replace")
    except (binascii.Error, ValueError) as e:
        return f"[error] {e}"


def hex_encode(s):
    return s.encode().hex()


OPS = {
    "urldec": url_decode,
    "urlenc": url_encode,
    "b64dec": b64_decode,
    "b64enc": b64_encode,
    "hexdec": hex_decode,
    "hexenc": hex_encode,
}


def run(op, text):
    fn = OPS.get(op)
    if not fn:
        return "[error] operasi tidak dikenal"
    return fn(text)
