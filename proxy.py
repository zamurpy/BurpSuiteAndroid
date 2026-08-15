# Author: ZamurSec | https://discord.com/invite/AA92kB5GSB
# (c) 2026 ZamurSec - All Rights Reserved. See LICENSE. Do not redistribute/modify without permission.

"""
proxy.py - Proxy HTTP/HTTPS dengan Intercept, mirip tab Proxy di Burp Suite.

- Semua request lewat proxy ini akan dicatat ke history.db
- Kalau intercept ON, request akan ditahan sampai user Forward/Drop/Edit
  lewat menu di main.py
"""
import socket
import ssl
import threading
import time
import queue
import uuid

import certauth
import db
import httputil

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8080
BUF = 65536

intercept_on = False
intercept_queue = queue.Queue()
_pending = {}   # id -> {"raw": bytes, "event": Event, "action": str, "edited": bytes}
_server_socket = None
_server_thread = None
_running = False


def _recv_until_headers_end(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(BUF)
        if not chunk:
            break
        data += chunk
    return data


def _read_full_request(sock):
    """Baca request line + headers + body (Content-Length aware)."""
    data = _recv_until_headers_end(sock)
    if not data:
        return None
    header_end = data.find(b"\r\n\r\n") + 4
    head = data[:header_end]
    body = data[header_end:]

    headers_text = head.decode(errors="replace")
    lines = headers_text.split("\r\n")
    request_line = lines[0]
    headers = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip()] = v.strip()

    content_length = int(headers.get("Content-Length", 0) or 0)
    while len(body) < content_length:
        chunk = sock.recv(BUF)
        if not chunk:
            break
        body += chunk

    return {
        "request_line": request_line,
        "headers": headers,
        "headers_raw": head,
        "body": body,
    }


def _read_full_response(sock):
    data = _recv_until_headers_end(sock)
    if not data:
        return None
    header_end = data.find(b"\r\n\r\n") + 4
    head = data[:header_end]
    body = data[header_end:]

    headers_text = head.decode(errors="replace")
    lines = headers_text.split("\r\n")
    status_line = lines[0]
    headers = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip()] = v.strip()

    if "chunked" in headers.get("Transfer-Encoding", "").lower():
        # baca sampai chunk terminator 0\r\n\r\n
        while not body.endswith(b"0\r\n\r\n"):
            chunk = sock.recv(BUF)
            if not chunk:
                break
            body += chunk
    elif "Content-Length" in headers:
        content_length = int(headers.get("Content-Length", 0) or 0)
        while len(body) < content_length:
            chunk = sock.recv(BUF)
            if not chunk:
                break
            body += chunk
    else:
        # tidak ada Content-Length maupun chunked -> baca sampai koneksi ditutup
        sock.settimeout(5)
        try:
            while True:
                chunk = sock.recv(BUF)
                if not chunk:
                    break
                body += chunk
        except socket.timeout:
            pass

    try:
        status = int(status_line.split(" ")[1])
    except Exception:
        status = 0

    return {
        "status_line": status_line,
        "status": status,
        "headers": headers,
        "headers_raw": head,
        "body": body,
    }


def _rebuild_request_bytes(request_line, headers_dict, body):
    lines = [request_line]
    for k, v in headers_dict.items():
        lines.append(f"{k}: {v}")
    head = "\r\n".join(lines) + "\r\n\r\n"
    return head.encode() + body


def maybe_intercept(raw_request_bytes, meta):
    """Kalau intercept ON, tahan request sampai user memutuskan.
    Return (action, final_bytes) -> action in ('forward','drop')"""
    global intercept_on
    if not intercept_on:
        return "forward", raw_request_bytes

    req_id = str(uuid.uuid4())[:8]
    ev = threading.Event()
    _pending[req_id] = {
        "raw": raw_request_bytes,
        "meta": meta,
        "event": ev,
        "action": None,
        "edited": None,
    }
    intercept_queue.put(req_id)
    ev.wait()  # blocking sampai user forward/drop di menu
    entry = _pending.pop(req_id)
    final = entry["edited"] if entry["edited"] is not None else entry["raw"]
    return entry["action"], final


def resolve_pending(req_id, action, edited_text=None):
    entry = _pending.get(req_id)
    if not entry:
        return False
    entry["action"] = action
    if edited_text is not None:
        entry["edited"] = edited_text.encode() if isinstance(edited_text, str) else edited_text
    entry["event"].set()
    return True


def list_pending():
    out = []
    for req_id in list(_pending.keys()):
        e = _pending.get(req_id)
        if e:
            out.append((req_id, e["meta"], e["raw"]))
    return out


def _method_and_path_from_raw(raw_bytes, fallback_method, fallback_path):
    """Ambil method+path aktual dari raw request (bisa beda kalau diedit di Intercept)."""
    try:
        first_line = raw_bytes.split(b"\r\n", 1)[0].decode(errors="replace")
        parts = first_line.split(" ")
        if len(parts) >= 2:
            return parts[0], parts[1]
    except Exception:
        pass
    return fallback_method, fallback_path


def _handle_plain_http(client_sock, first_req, method, target_host, target_port, path):
    start = time.time()
    headers = dict(first_req["headers"])
    headers["Connection"] = "close"
    request_line = f"{method} {path} HTTP/1.1"
    raw = _rebuild_request_bytes(request_line, headers, first_req["body"])

    action, final_raw = maybe_intercept(raw, {
        "method": method, "host": target_host, "url": f"http://{target_host}{path}"
    })
    if action == "drop":
        client_sock.close()
        return

    # Kalau request diedit di Intercept, method/path bisa berubah -> re-parse
    actual_method, actual_path = _method_and_path_from_raw(final_raw, method, path)

    try:
        remote = socket.create_connection((target_host, target_port), timeout=15)
        remote.sendall(final_raw)
        resp = _read_full_response(remote)
        remote.close()
    except Exception as e:
        client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n" + str(e).encode())
        client_sock.close()
        return

    elapsed_ms = int((time.time() - start) * 1000)
    if resp:
        client_sock.sendall(resp["headers_raw"] + resp["body"])
        decoded_body = httputil.decode_response_body(resp["headers"], resp["body"])
        db.save_history(actual_method, "http", target_host, f"http://{target_host}{actual_path}",
                         final_raw.decode(errors="replace"),
                         first_req["body"].decode(errors="replace")[:20000],
                         resp["status"], resp["headers_raw"].decode(errors="replace"),
                         decoded_body[:20000], elapsed_ms,
                         port=target_port)
    client_sock.close()


def _handle_connect_https(client_sock, target_host, target_port):
    # beri tahu client bahwa tunnel siap
    client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

    if not certauth.HAVE_CRYPTO:
        # fallback: passthrough tanpa decrypt (tidak bisa lihat isi, tapi tetap jalan)
        _tunnel_raw(client_sock, target_host, target_port)
        return

    certfile, keyfile = certauth.get_cert_for_host(target_host)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    try:
        tls_client = ctx.wrap_socket(client_sock, server_side=True)
    except Exception:
        client_sock.close()
        return

    try:
        while True:
            req = _read_full_request(tls_client)
            if not req or not req["request_line"]:
                break
            parts = req["request_line"].split(" ")
            if len(parts) < 2:
                break
            method, path = parts[0], parts[1]
            start = time.time()
            headers = dict(req["headers"])
            headers["Connection"] = "close"
            raw = _rebuild_request_bytes(f"{method} {path} HTTP/1.1", headers, req["body"])

            action, final_raw = maybe_intercept(raw, {
                "method": method, "host": target_host,
                "url": f"https://{target_host}{path}"
            })
            if action == "drop":
                break

            remote_ctx = ssl.create_default_context()
            remote_ctx.check_hostname = False
            remote_ctx.verify_mode = ssl.CERT_NONE
            raw_sock = socket.create_connection((target_host, target_port), timeout=15)
            remote = remote_ctx.wrap_socket(raw_sock, server_hostname=target_host)
            remote.sendall(final_raw)
            resp = _read_full_response(remote)
            remote.close()

            actual_method, actual_path = _method_and_path_from_raw(final_raw, method, path)

            elapsed_ms = int((time.time() - start) * 1000)
            if resp:
                tls_client.sendall(resp["headers_raw"] + resp["body"])
                decoded_body = httputil.decode_response_body(resp["headers"], resp["body"])
                db.save_history(actual_method, "https", target_host, f"https://{target_host}{actual_path}",
                                 final_raw.decode(errors="replace"),
                                 req["body"].decode(errors="replace")[:20000],
                                 resp["status"], resp["headers_raw"].decode(errors="replace"),
                                 decoded_body[:20000], elapsed_ms,
                                 port=target_port)
            else:
                break
            if headers.get("Connection", "").lower() == "close":
                break
    except Exception:
        pass
    finally:
        try:
            tls_client.close()
        except Exception:
            pass


def _tunnel_raw(client_sock, target_host, target_port):
    try:
        remote = socket.create_connection((target_host, target_port), timeout=15)
    except Exception:
        client_sock.close()
        return

    def pipe(a, b):
        try:
            while True:
                data = a.recv(BUF)
                if not data:
                    break
                b.sendall(data)
        except Exception:
            pass
        finally:
            try:
                a.close()
            except Exception:
                pass
            try:
                b.close()
            except Exception:
                pass

    t1 = threading.Thread(target=pipe, args=(client_sock, remote), daemon=True)
    t2 = threading.Thread(target=pipe, args=(remote, client_sock), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


def _client_thread(client_sock, addr):
    try:
        req = _read_full_request(client_sock)
        if not req or not req["request_line"]:
            client_sock.close()
            return

        parts = req["request_line"].split(" ")
        if len(parts) < 2:
            client_sock.close()
            return
        method, target = parts[0], parts[1]

        if method == "CONNECT":
            host_port = target
            host, _, port = host_port.partition(":")
            port = int(port) if port else 443
            _handle_connect_https(client_sock, host, port)
        else:
            # target biasanya full URL: http://host:port/path
            if target.startswith("http://"):
                rest = target[len("http://"):]
                host_part, _, path = rest.partition("/")
                path = "/" + path
            else:
                path = target
                host_part = req["headers"].get("Host", "")

            host, _, port = host_part.partition(":")
            port = int(port) if port else 80
            _handle_plain_http(client_sock, req, method, host, port, path)
    except Exception:
        try:
            client_sock.close()
        except Exception:
            pass


def _serve():
    global _server_socket, _running
    _server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _server_socket.bind((LISTEN_HOST, LISTEN_PORT))
    _server_socket.listen(100)
    _running = True
    while _running:
        try:
            _server_socket.settimeout(1.0)
            try:
                client_sock, addr = _server_socket.accept()
            except socket.timeout:
                continue
            threading.Thread(target=_client_thread, args=(client_sock, addr), daemon=True).start()
        except OSError:
            break


def start():
    global _server_thread
    db.init_db()
    if certauth.HAVE_CRYPTO:
        certauth.ensure_root_ca()
    if _server_thread and _server_thread.is_alive():
        return False
    _server_thread = threading.Thread(target=_serve, daemon=True)
    _server_thread.start()
    return True


def stop():
    global _running, _server_socket
    _running = False
    if _server_socket:
        try:
            _server_socket.close()
        except Exception:
            pass


def toggle_intercept():
    global intercept_on
    intercept_on = not intercept_on
    if not intercept_on:
        # Sama seperti Burp asli: kalau Intercept dimatikan, semua request
        # yang masih tertahan otomatis di-forward, biar gak nyangkut selamanya.
        for req_id in list(_pending.keys()):
            resolve_pending(req_id, "forward")
    return intercept_on
