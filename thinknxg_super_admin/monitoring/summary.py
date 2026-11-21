"""Pure helpers for dashboard aggregation (no ``frappe`` import)."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import date, datetime, timedelta

CONNECTION_ORDER = ("Online", "Degraded", "Offline", "Unknown")
REQUEST_OUTCOMES = ("Succeeded", "Failed", "Needs Review", "Retrying", "Queued", "Running", "Cancelled")


def fill_counts(rows: Iterable[Mapping], key: str, keys: Sequence[str], count: str = "n") -> dict[str, int]:
	"""Counts per known key with zeros filled in. Unknown values are grouped under ``Other``."""
	out = dict.fromkeys(keys, 0)
	for row in rows:
		label = row.get(key)
		if label in out:
			out[label] += int(row.get(count) or 0)
		else:
			out["Other"] = out.get("Other", 0) + int(row.get(count) or 0)
	return out


def daily_buckets(rows: Iterable[Mapping], days: int, today: date, outcomes: Sequence[str] = REQUEST_OUTCOMES) -> list[dict]:
	"""One bucket per day, oldest first, ending today. ``rows``: ``{day, status, n}``."""
	buckets = {today - timedelta(days=i): dict.fromkeys(outcomes, 0) for i in range(days - 1, -1, -1)}
	for row in rows:
		day = row["day"].date() if isinstance(row["day"], datetime) else row["day"]
		if day in buckets and row["status"] in buckets[day]:
			buckets[day][row["status"]] += int(row.get("n") or 0)
	return [{"day": d.isoformat(), **counts} for d, counts in buckets.items()]


_ATTENTION_RANK = {"Offline": 0, "Degraded": 1, "Unknown": 2}


def rank_sites_needing_attention(sites: Iterable[Mapping], limit: int = 20) -> list[dict]:
	"""Active sites that are not Online, worst first, then by oldest health check."""
	pool = [s for s in sites if s.get("status") == "Active" and s.get("connection_status") in _ATTENTION_RANK]
	pool.sort(key=lambda s: (_ATTENTION_RANK[s["connection_status"]], s.get("last_health_check") or datetime.min))
	return [dict(s) for s in pool[:limit]]


def clip(text: str | None, limit: int = 140) -> str:
	text = (text or "").replace("\n", " ").strip()
	return text if len(text) <= limit else text[: limit - 1] + "\u2026"
