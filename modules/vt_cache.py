from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from modules.url_analysis import query_virustotal_url, URLReputation


DB_PATH_DEFAULT = Path("outputs") / "vt_cache.sqlite"
CACHE_TTL_DAYS_DEFAULT = 7


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class VTCache:
    def __init__(
        self,
        db_path: str | Path = DB_PATH_DEFAULT,
        ttl_days: int = CACHE_TTL_DAYS_DEFAULT,
    ):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.ttl_days = ttl_days
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS vt_url_cache (
                    url            TEXT    PRIMARY KEY,
                    fetched_at_utc TEXT    NOT NULL,
                    verdict        TEXT    NOT NULL,
                    vt_malicious   INTEGER NOT NULL,
                    vt_suspicious  INTEGER NOT NULL,
                    vt_harmless    INTEGER NOT NULL,
                    vt_undetected  INTEGER NOT NULL,
                    vt_timeout     INTEGER NOT NULL,
                    stats_json     TEXT
                );
                """
            )

            existing_cols = {
                row[1]
                for row in conn.execute("PRAGMA table_info(vt_url_cache)")
            }

            if "raw_json" in existing_cols and "stats_json" not in existing_cols:
                conn.execute(
                    "ALTER TABLE vt_url_cache ADD COLUMN stats_json TEXT"
                )
                rows = conn.execute(
                    "SELECT url, raw_json FROM vt_url_cache WHERE raw_json IS NOT NULL"
                ).fetchall()
                for row in rows:
                    try:
                        raw = json.loads(row["raw_json"])
                        stats = (
                            raw.get("data", {})
                               .get("attributes", {})
                               .get("last_analysis_stats", {})
                        )
                        conn.execute(
                            "UPDATE vt_url_cache SET stats_json = ? WHERE url = ?",
                            (json.dumps(stats), row["url"]),
                        )
                    except Exception:
                        pass

            conn.commit()

    def _is_fresh(self, fetched_at_utc: str) -> bool:
        try:
            fetched_dt = datetime.fromisoformat(fetched_at_utc)
        except ValueError:
            return False
        if fetched_dt.tzinfo is None:
            fetched_dt = fetched_dt.replace(tzinfo=timezone.utc)
        return fetched_dt >= (_utcnow() - timedelta(days=self.ttl_days))

    def get(self, url: str) -> Optional[URLReputation]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM vt_url_cache WHERE url = ?", (url,)
            ).fetchone()

            if not row:
                return None
            if not self._is_fresh(row["fetched_at_utc"]):
                return None

            try:
                stats = json.loads(row["stats_json"]) if row["stats_json"] else {}
            except (json.JSONDecodeError, TypeError):
                stats = {}

            return URLReputation(
                url=row["url"],
                vt_malicious=row["vt_malicious"],
                vt_suspicious=row["vt_suspicious"],
                vt_harmless=row["vt_harmless"],
                vt_undetected=row["vt_undetected"],
                vt_timeout=row["vt_timeout"],
                verdict=row["verdict"],
                stats_summary=stats,
            )

    def set(self, rep: URLReputation) -> None:
        stats_json = json.dumps(rep.stats_summary) if rep.stats_summary else "{}"

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO vt_url_cache (
                    url, fetched_at_utc, verdict,
                    vt_malicious, vt_suspicious, vt_harmless,
                    vt_undetected, vt_timeout, stats_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(url) DO UPDATE SET
                    fetched_at_utc = excluded.fetched_at_utc,
                    verdict        = excluded.verdict,
                    vt_malicious   = excluded.vt_malicious,
                    vt_suspicious  = excluded.vt_suspicious,
                    vt_harmless    = excluded.vt_harmless,
                    vt_undetected  = excluded.vt_undetected,
                    vt_timeout     = excluded.vt_timeout,
                    stats_json     = excluded.stats_json;
                """,
                (
                    rep.url,
                    _utcnow().isoformat(),
                    rep.verdict,
                    rep.vt_malicious,
                    rep.vt_suspicious,
                    rep.vt_harmless,
                    rep.vt_undetected,
                    rep.vt_timeout,
                    stats_json,
                ),
            )
            conn.commit()

    def get_or_query(self, url: str) -> URLReputation:
        cached = self.get(url)
        if cached:
            return cached
        rep = query_virustotal_url(url)
        self.set(rep)
        return rep

    def purge_stale(self) -> int:
        cutoff = (_utcnow() - timedelta(days=self.ttl_days)).isoformat()
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM vt_url_cache WHERE fetched_at_utc < ?",
                (cutoff,),
            )
            conn.commit()
            return cursor.rowcount

    def stats(self) -> dict:
        """Return a summary of cache contents."""
        with self._connect() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM vt_url_cache"
            ).fetchone()[0]
            fresh = conn.execute(
                "SELECT COUNT(*) FROM vt_url_cache WHERE fetched_at_utc >= ?",
                ((_utcnow() - timedelta(days=self.ttl_days)).isoformat(),),
            ).fetchone()[0]
            return {
                "total_entries":  total,
                "fresh_entries":  fresh,
                "stale_entries":  total - fresh,
                "ttl_days":       self.ttl_days,
                "db_path":        str(self.db_path),
            }