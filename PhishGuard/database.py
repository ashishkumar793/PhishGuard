"""SQLite storage for scan history."""
import json
import sqlite3
from datetime import datetime

DB_PATH = "phishguard.db"


def get_conn(path=None):
    conn = sqlite3.connect(path or DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(path=None):
    with get_conn(path) as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                reasons TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            )"""
        )


def save_scan(result, path=None):
    with get_conn(path) as conn:
        cur = conn.execute(
            "INSERT INTO scans (url, score, verdict, reasons, scanned_at) VALUES (?,?,?,?,?)",
            (result["url"], result["score"], result["verdict"],
             json.dumps(result["reasons"]), datetime.now().isoformat(timespec="seconds")),
        )
        return cur.lastrowid


def get_history(limit=100, verdict=None, path=None):
    query = "SELECT * FROM scans"
    params = []
    if verdict:
        query += " WHERE verdict = ?"
        params.append(verdict)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with get_conn(path) as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(r, reasons=json.loads(r["reasons"])) for r in rows]


def get_stats(path=None):
    with get_conn(path) as conn:
        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        by_verdict = {r["verdict"]: r["n"] for r in conn.execute(
            "SELECT verdict, COUNT(*) AS n FROM scans GROUP BY verdict")}
        avg = conn.execute("SELECT AVG(score) FROM scans").fetchone()[0] or 0
        top = [dict(r) for r in conn.execute(
            "SELECT url, score FROM scans ORDER BY score DESC, id DESC LIMIT 5")]
    return {"total": total, "by_verdict": by_verdict, "average": round(avg, 1), "top": top}


def clear_history(path=None):
    with get_conn(path) as conn:
        conn.execute("DELETE FROM scans")
