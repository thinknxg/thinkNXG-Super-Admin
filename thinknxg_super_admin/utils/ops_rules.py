"""Pure verdict for the external health check. No Frappe imports."""

from datetime import datetime, timedelta

MAX_EVALUATION_AGE = timedelta(minutes=15)  # the evaluator runs every 5 minutes


def health_verdict(
	*, db_ok: bool, last_evaluated_at: datetime | None, now: datetime, max_age: timedelta = MAX_EVALUATION_AGE
) -> tuple[bool, str]:
	"""Return ``(ok, reason)``. A stopped scheduler means no alert would ever fire, so it is a failure."""
	if not db_ok:
		return False, "database"
	if last_evaluated_at is None:
		return False, "scheduler_never_ran"
	if now - last_evaluated_at > max_age:
		return False, "scheduler_stale"
	return True, "ok"
