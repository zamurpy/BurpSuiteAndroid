#!/usr/bin/env python3
# Author: ZamurSec | https://discord.com/invite/AA92kB5GSB
# (c) 2026 ZamurSec - All Rights Reserved. See LICENSE. Do not redistribute/modify without permission.
"""
app.py - Web UI backend untuk Ethical Hacking Burp.
Jalankan: python app.py
Buka di browser (device yang sama / Termux browser): http://127.0.0.1:5000

PERINGATAN: hanya untuk pengujian pada sistem yang kamu miliki atau
punya izin eksplisit untuk diuji.
"""
import os
from flask import Flask, request, jsonify, send_from_directory

import db
import proxy
import repeater
import intruder
import decoder
import certauth
import httputil

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")


@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/api/proxy/status")
def proxy_status():
    return jsonify({
        "running": proxy._running,
        "host": proxy.LISTEN_HOST,
        "port": proxy.LISTEN_PORT,
        "intercept": proxy.intercept_on,
        "has_tls": certauth.HAVE_CRYPTO,
    })


@app.route("/api/proxy/start", methods=["POST"])
def proxy_start():
    ok = proxy.start()
    return jsonify({"ok": ok, "running": proxy._running})


@app.route("/api/proxy/stop", methods=["POST"])
def proxy_stop():
    proxy.stop()
    return jsonify({"ok": True, "running": proxy._running})


@app.route("/api/proxy/port", methods=["POST"])
def proxy_set_port():
    if proxy._running:
        return jsonify({"ok": False, "error": "Stop proxy dulu sebelum ganti port."}), 400
    data = request.get_json(force=True)
    try:
        proxy.LISTEN_PORT = int(data.get("port"))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "Port tidak valid"}), 400
    return jsonify({"ok": True, "port": proxy.LISTEN_PORT})


@app.route("/api/proxy/ca")
def proxy_ca_info():
    if not certauth.HAVE_CRYPTO:
        return jsonify({"available": False, "message": "Module 'cryptography' belum terinstall."})
    key_path, cert_path = certauth.ensure_root_ca()
    return jsonify({"available": True, "cert_path": cert_path, "key_path": key_path})


@app.route("/api/intercept/toggle", methods=["POST"])
def intercept_toggle():
    state = proxy.toggle_intercept()
    return jsonify({"intercept": state})


@app.route("/api/intercept/pending")
def intercept_pending():
    out = []
    for req_id, meta, raw in proxy.list_pending():
        out.append({
            "id": req_id,
            "method": meta["method"],
            "url": meta["url"],
            "host": meta["host"],
            "raw": raw.decode(errors="replace"),
        })
    return jsonify(out)


@app.route("/api/intercept/<req_id>/forward", methods=["POST"])
def intercept_forward(req_id):
    data = request.get_json(silent=True) or {}
    edited = data.get("raw")
    ok = proxy.resolve_pending(req_id, "forward", edited)
    return jsonify({"ok": ok})


@app.route("/api/intercept/<req_id>/drop", methods=["POST"])
def intercept_drop(req_id):
    ok = proxy.resolve_pending(req_id, "drop")
    return jsonify({"ok": ok})


@app.route("/api/history")
def history_list():
    limit = int(request.args.get("limit", 15))
    offset = int(request.args.get("offset", 0))
    host = request.args.get("host") or None
    rows = db.list_history(limit=limit, offset=offset, host=host)
    total = db.count_history(host=host)
    return jsonify({
        "items": [dict(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    })


@app.route("/api/history/hosts")
def history_hosts():
    return jsonify(db.list_hosts())


@app.route("/api/history/<int:entry_id>")
def history_detail(entry_id):
    row = db.get_history(entry_id)
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


@app.route("/api/history/clear", methods=["POST"])
def history_clear():
    db.clear_history()
    return jsonify({"ok": True})


@app.route("/api/repeater/send", methods=["POST"])
def repeater_send():
    data = request.get_json(force=True)
    host = data.get("host")
    port = int(data.get("port", 80))
    use_tls = bool(data.get("tls", False))
    raw_text = data.get("raw", "")

    if not raw_text.endswith("\r\n\r\n"):
        # pastikan header diakhiri dengan baris kosong
        raw_text = raw_text.rstrip("\r\n") + "\r\n\r\n"

    try:
        resp_bytes, elapsed_ms = repeater.send_raw(host, port, use_tls, raw_text.encode())
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 502

    headers_text, headers, body = httputil.parse_raw_response(resp_bytes)
    decoded_body = httputil.decode_response_body(headers, body)
    display_response = headers_text + "\r\n\r\n" + decoded_body

    return jsonify({
        "ok": True,
        "elapsed_ms": elapsed_ms,
        "response": display_response,
    })


@app.route("/api/repeater/from_history/<int:entry_id>")
def repeater_from_history(entry_id):
    row = db.get_history(entry_id)
    if not row:
        return jsonify({"error": "not found"}), 404
    port = row["port"] if row["port"] else (443 if row["scheme"] == "https" else 80)
    return jsonify({
        "host": row["host"],
        "port": port,
        "tls": row["scheme"] == "https",
        "raw": row["req_headers"] + row["req_body"],
    })


@app.route("/api/intruder/attack", methods=["POST"])
def intruder_attack():
    data = request.get_json(force=True)
    host = data.get("host")
    port = int(data.get("port", 80))
    use_tls = bool(data.get("tls", False))
    template = data.get("template", "")
    payloads_raw = data.get("payloads", "")
    threads = int(data.get("threads", 5))

    payloads = [p.strip() for p in payloads_raw.splitlines() if p.strip()]
    if not payloads:
        return jsonify({"ok": False, "error": "Payload kosong"}), 400
    if intruder.MARKER not in template:
        return jsonify({"ok": False, "error": f"Template harus mengandung marker {intruder.MARKER}"}), 400

    if not template.endswith("\r\n\r\n"):
        template = template.rstrip("\r\n") + "\r\n\r\n"

    results = intruder.run_attack(host, port, use_tls, template, payloads, threads=threads)
    return jsonify({"ok": True, "results": results})


@app.route("/api/decoder", methods=["POST"])
def decoder_run():
    data = request.get_json(force=True)
    op = data.get("op")
    text = data.get("text", "")
    result = decoder.run(op, text)
    return jsonify({"result": result})


if __name__ == "__main__":
    db.init_db()
    if certauth.HAVE_CRYPTO:
        certauth.ensure_root_ca()
    print("\n=== Ethical Hacking Burp - Web UI ===")
    print("Buka di browser: http://127.0.0.1:5000")
    print("PERINGATAN: hanya untuk sistem yang kamu miliki / punya izin diuji.\n")
    app.run(host="127.0.0.1", port=5000, threaded=True)
