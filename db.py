# Author: ZamurSec | https://discord.com/invite/AA92kB5GSB
# (c) 2026 ZamurSec - All Rights Reserved. See LICENSE. Do not redistribute/modify without permission.

"""
db.py - Penyimpanan history request/response (mirip HTTP History di Burp)
"""
import sqlite3
import os
import threading
import time

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "history.db")
_lock = threading.Lock()


def _connect():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _lock:
        conn = _connect()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                method TEXT,
                scheme TEXT,
                host TEXT,
                port INTEGER,
                url TEXT,
                req_headers TEXT,
                req_body TEXT,
                status INTEGER,
                resp_headers TEXT,
                resp_body TEXT,
                time_ms INTEGER
            )
            """
        )
        conn.commit()
        conn.close()


def save_history(method, scheme, host, url, req_headers, req_body,
                  status, resp_headers, resp_body, time_ms, port=None):
    if port is None:
        port = 443 if scheme == "https" else 80
    with _lock:
        conn = _connect()
        cur = conn.execute(
            """INSERT INTO history
               (timestamp, method, scheme, host, port, url, req_headers, req_body,
                status, resp_headers, resp_body, time_ms)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                time.strftime("%Y-%m-%d %H:%M:%S"),
                method, scheme, host, port, url,
                req_headers, req_body or "",
                status, resp_headers or "", resp_body or "",
                time_ms,
            ),
        )
        conn.commit()
        rowid = cur.lastrowid
        conn.close()
        return rowid


def list_history(limit=15, offset=0, host=None):
    with _lock:
        conn = _connect()
        if host:
            rows = conn.execute(
                "SELECT id, timestamp, method, host, url, status, time_ms "
                "FROM history WHERE host = ? ORDER BY id DESC LIMIT ? OFFSET ?",
                (host, limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, timestamp, method, host, url, status, time_ms "
                "FROM history ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        conn.close()
        return rows


def count_history(host=None):
    with _lock:
        conn = _connect()
        if host:
            row = conn.execute("SELECT COUNT(*) as c FROM history WHERE host = ?", (host,)).fetchone()
        else:
            row = conn.execute("SELECT COUNT(*) as c FROM history").fetchone()
        conn.close()
        return row["c"]


def list_hosts():
    """Daftar host unik yang pernah lewat, buat dropdown filter di History."""
    with _lock:
        conn = _connect()
        rows = conn.execute(
            "SELECT host, COUNT(*) as cnt FROM history GROUP BY host ORDER BY cnt DESC"
        ).fetchall()
        conn.close()
        return [{"host": r["host"], "count": r["cnt"]} for r in rows]


def get_history(entry_id):
    with _lock:
        conn = _connect()
        row = conn.execute("SELECT * FROM history WHERE id=?", (entry_id,)).fetchone()
        conn.close()
        return row


def clear_history():
    with _lock:
        conn = _connect()
        conn.execute("DELETE FROM history")
        conn.commit()
        conn.close()
