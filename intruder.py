# Author: ZamurSec | https://discord.com/invite/AA92kB5GSB
# (c) 2026 ZamurSec - All Rights Reserved. See LICENSE. Do not redistribute/modify without permission.

"""
intruder.py - Sniper attack fuzzer, mirip tab Intruder di Burp Suite.
Marker payload: §PAYLOAD§ di dalam raw request template.
"""
import socket
import ssl
import time
import csv
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

MARKER = "\u00a7PAYLOAD\u00a7"  # §PAYLOAD§


def _send_one(host, port, use_tls, raw_bytes, timeout=10):
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw_sock = socket.create_connection((host, port), timeout=timeout)
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = socket.create_connection((host, port), timeout=timeout)

        start = time.time()
        sock.sendall(raw_bytes)
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

        status = 0
        if data:
            try:
                status_line = data.split(b"\r\n", 1)[0].decode(errors="replace")
                status = int(status_line.split(" ")[1])
            except Exception:
                status = 0
        return status, len(data), elapsed_ms, None
    except Exception as e:
        return 0, 0, 0, str(e)


def run_attack(host, port, use_tls, raw_template, payloads, threads=5,
                output_csv=None):
    """raw_template: string request mentah berisi MARKER di lokasi yg mau di-fuzz."""
    if MARKER not in raw_template:
        print(f"[!] Template tidak mengandung marker {MARKER}. Tambahkan dulu di posisi yang mau di-fuzz.")
        return []

    results = []

    def task(payload):
        req_text = raw_template.replace(MARKER, payload)
        raw_bytes = req_text.encode()
        status, length, ms, err = _send_one(host, port, use_tls, raw_bytes)
        return payload, status, length, ms, err

    print(f"\n[*] Menjalankan {len(payloads)} payload ke {host}:{port} ({threads} threads)...")
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(task, p) for p in payloads]
        for i, fut in enumerate(as_completed(futures), 1):
            payload, status, length, ms, err = fut.result()
            results.append({
                "payload": payload, "status": status,
                "length": length, "time_ms": ms, "error": err or ""
            })
            status_show = err if err else status
            print(f"[{i}/{len(payloads)}] payload={payload!r:30} status={status_show} len={length} time={ms}ms")

    results.sort(key=lambda r: r["payload"])

    if output_csv:
        with open(output_csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["payload", "status", "length", "time_ms", "error"])
            writer.writeheader()
            writer.writerows(results)
        print(f"\n[+] Hasil disimpan ke {output_csv}")

    return results


def load_payloads_from_file(path):
    if not os.path.exists(path):
        print(f"[!] File tidak ditemukan: {path}")
        return []
    with open(path, "r", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def interactive_intruder():
    print("\n=== INTRUDER ===")
    print(f"Gunakan marker {MARKER} di posisi yang ingin di-fuzz dalam raw request.")
    host = input("Target host: ").strip()
    port_in = input("Port (default 80, https pakai 443): ").strip()
    port = int(port_in) if port_in else 80
    use_tls = input("Pakai HTTPS/TLS? (y/N): ").strip().lower() == "y"

    print("\nMasukkan raw request template (akhiri dengan baris 'END' di baris sendiri):")
    print(f"Contoh baris pertama: GET /login?user={MARKER} HTTP/1.1")
    lines = []
    while True:
        line = input()
        if line.strip() == "END":
            break
        lines.append(line)
    template = "\r\n".join(lines) + "\r\n\r\n"

    src = input("\nSumber payload - (1) ketik manual dipisah koma, (2) dari file wordlist: ").strip()
    if src == "2":
        path = input("Path file wordlist: ").strip()
        payloads = load_payloads_from_file(path)
    else:
        raw = input("Payload (pisahkan dengan koma): ").strip()
        payloads = [p.strip() for p in raw.split(",") if p.strip()]

    if not payloads:
        print("Tidak ada payload, batal.")
        return

    threads_in = input("Jumlah thread (default 5): ").strip()
    threads = int(threads_in) if threads_in else 5

    out = input("Simpan hasil ke CSV? (kosongkan untuk skip, atau isi nama file): ").strip()
    output_csv = out if out else None

    run_attack(host, port, use_tls, template, payloads, threads, output_csv)
