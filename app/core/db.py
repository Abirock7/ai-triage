# app/core/db.py
import os
import aiosqlite

DB_PATH = os.getenv("DB_PATH", "triage.db")

async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            created_at TEXT,
            xml_path TEXT,
            parsed_json TEXT,
            llm_summary TEXT
        )
        """)
        await db.commit()

async def insert_scan(ip, created_at, xml_path, parsed_json, llm_summary) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "INSERT INTO scans (ip, created_at, xml_path, parsed_json, llm_summary) VALUES (?, ?, ?, ?, ?)",
            (ip, created_at, xml_path, parsed_json, llm_summary)
        )
        await db.commit()
        return cur.lastrowid

async def list_scans():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT id, ip, created_at FROM scans ORDER BY id DESC"
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]

async def get_scan(scan_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = await cur.fetchone()
        return dict(row) if row else None
