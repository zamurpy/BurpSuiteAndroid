# Author: ZamurSec | https://discord.com/invite/AA92kB5GSB
# (c) 2026 ZamurSec - All Rights Reserved. See LICENSE. Do not redistribute/modify without permission.

"""
repeater.py - Ambil request dari history, edit manual, kirim ulang.
Mirip tab Repeater di Burp Suite.
"""
import socket
import ssl
import time

import db
import httputil


def send_raw(host, port, use_tls, raw_request_bytes, timeout=15):
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        sock = ctx.wrap_socket(raw_sock, server_hostname=host)
    else:
        sock = socket.create_connection((host, port), timeout=timeout)

    start = time.time()
    sock.sendall(raw_request_bytes)

    data = b""
    sock.settimeout(timeout)
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    sock.close()
    elapsed_ms = int((time.time() - start) * 1000)
    return data, elapsed_ms


def repeat_from_history(entry_id, edited_raw_text=None):
    row = db.get_history(entry_id)
    if not row:
        print(f"[!] History id {entry_id} tidak ditemukan.")
        return

    host = row["host"]
    scheme = row["scheme"]
    port = row["port"] if row["port"] else (443 if scheme == "https" else 80)

    raw_text = edited_raw_text if edited_raw_text is not None else row["req_headers"]
    body = "" if edited_raw_text is not None else row["req_body"]

    if edited_raw_text is not None:
        raw_bytes = raw_text.encode()
    else:
        raw_bytes = (raw_text + body).encode() if not raw_text.endswith("\r\n\r\n") else raw_text.encode() + body.encode()

    print(f"\n--- Mengirim ke {host}:{port} ({scheme}) ---")
    resp, elapsed = send_raw(host, port, scheme == "https", raw_bytes)
    print(f"--- Response ({elapsed} ms) ---")
    headers_text, headers, body = httputil.parse_raw_response(resp)
    decoded_body = httputil.decode_response_body(headers, body)
    print((headers_text + "\r\n\r\n" + decoded_body)[:4000])
    return resp, elapsed


def interactive_repeater():
    rows = db.list_history(limit=20)
    if not rows:
        print("Belum ada history. Jalankan proxy dulu dan tangkap traffic.")
        return
    print("\n=== HISTORY TERBARU ===")
    for r in rows:
        print(f"[{r['id']}] {r['method']} {r['url']} -> {r['status']} ({r['time_ms']}ms)")

    try:
        entry_id = int(input("\nPilih ID untuk di-repeat: ").strip())
    except ValueError:
        print("ID tidak valid.")
        return

    row = db.get_history(entry_id)
    if not row:
        print("ID tidak ditemukan.")
        return

    print("\n--- Raw request saat ini ---")
    print(row["req_headers"])
    edit = input("\nEdit request? (y/N): ").strip().lower()
    edited = None
    if edit == "y":
        print("Masukkan request baru, akhiri dengan baris kosong lalu ketik END:")
        lines = []
        while True:
            line = input()
            if line.strip() == "END":
                break
            lines.append(line)
        edited = "\r\n".join(lines) + "\r\n\r\n"

    repeat_from_history(entry_id, edited)
