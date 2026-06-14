import sqlite3
import json
import time
from pathlib import Path
import threading


class SimpleCache:
    def __init__(self, db_path="./vt_cache.db"):
        self.db_path = Path(db_path)
        # Allow usage across FastAPI's threadpool workers; guard with a lock
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.lock = threading.Lock()
        self._ensure()

    def _ensure(self):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute("CREATE TABLE IF NOT EXISTS cache(key TEXT PRIMARY KEY, value TEXT, ts REAL)")
            self.conn.commit()

    def get(self, key):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT value, ts FROM cache WHERE key=?", (key,))
            row = cur.fetchone()
            if not row:
                return None
            return json.loads(row[0])

    def set(self, key, value):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("REPLACE INTO cache(key,value,ts) VALUES(?,?,?)", (key, json.dumps(value), time.time()))
            self.conn.commit()
