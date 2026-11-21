
## Phase 7: dashboards and alerts

* **Overview page** (`/app/thinknxg-overview`): site health, users, assignments, 7-day provisioning chart,
  open alerts, sites and requests needing attention, recent sign-ins. Aggregated server-side by
  `api.dashboard.overview`; Org Admins see only their organizations and an Org Admin with none sees nothing.
  Refreshes every 60 seconds while the tab is visible.
* **Alerts** (`ThinkNXG Alert`, one document per condition key): site offline/degraded/stale health,
  provisioning needing review too long, repeated failures, access-denied spikes, stuck queue.
  Evaluated every 5 minutes under a cache lock. Lifecycle: opened, escalated, reminded (every
  `renotify_hours`), resolved. Acknowledged alerts are not reminded but still escalate and resolve.
* **Delivery**: in-app `Notification Log` entries and one email digest per recipient per run. Recipients:
  Super Admins, Org Admins scoped to the alert's organization, plus extra addresses (email only).
  Email honours `enable_email` and `email_min_severity`. Mail failure is logged and never blocks in-app delivery.
  Notification Log type "Alert" is skipped by core auto-email, so email is sent explicitly and not duplicated.
* **Settings**: `ThinkNXG Alert Settings` (Super Admin only).
* **Login activity**: sites report successful logins (signed, rate limited, only for users with an assignment).
* **Retention** (daily): resolved alerts 90 days, login activity 180 days.

Not run against a live bench: controllers, scheduler jobs, the page and mail delivery are unexecuted.
