frappe.pages["thinknxg-overview"].on_page_load = function (wrapper) {
	const page = frappe.ui.make_app_page({
		parent: wrapper,
		title: __("thinkNXG Overview"),
		single_column: true,
	});
	const body = $('<div class="tnxg-overview"></div>').appendTo(page.main);
	const esc = frappe.utils.escape_html;

	const pill = (text, color) => `<span class="indicator-pill ${color}">${esc(text)}</span>`;
	const sevColor = { Critical: "red", Warning: "orange", Info: "blue" };
	const connColor = { Online: "green", Degraded: "orange", Offline: "red", Unknown: "gray" };
	const link = (doctype, name, label) =>
		`<a href="/app/${frappe.router.slug(doctype)}/${encodeURIComponent(name)}">${esc(label || name)}</a>`;

	const tile = (label, value, color) =>
		`<div class="col-sm-6 col-md-3" style="margin-bottom:12px"><div class="frappe-card" style="padding:12px 16px">
			<div class="text-muted small">${esc(label)}</div>
			<div style="font-size:24px;font-weight:600">${esc(String(value))}</div>${color ? pill(color.label, color.c) : ""}</div></div>`;

	const table = (title, headers, rows, empty) =>
		`<div class="frappe-card" style="padding:12px 16px;margin-bottom:12px"><h5>${esc(title)}</h5>` +
		(rows.length
			? `<table class="table table-sm"><thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${rows
					.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`)
					.join("")}</tbody></table>`
			: `<div class="text-muted">${esc(empty)}</div>`) +
		"</div>";

	const bars = (days) => {
		const max = Math.max(1, ...days.map((d) => d.Succeeded + d.Failed + d["Needs Review"] + d.Retrying + d.Queued + d.Running));
		return days
			.map((d) => {
				const total = d.Succeeded + d.Failed + d["Needs Review"] + d.Retrying + d.Queued + d.Running;
				const h = (n) => Math.round((n / max) * 100);
				return `<div style="display:inline-block;width:12%;text-align:center;vertical-align:bottom">
					<div style="height:100px;display:flex;flex-direction:column-reverse;margin:0 6px" title="${esc(d.day)}: ${total}">
						<div style="background:var(--green-500);height:${h(d.Succeeded)}px"></div>
						<div style="background:var(--orange-500);height:${h(d["Needs Review"] + d.Retrying + d.Queued + d.Running)}px"></div>
						<div style="background:var(--red-500);height:${h(d.Failed)}px"></div></div>
					<div class="small text-muted">${esc(d.day.slice(5))}</div></div>`;
			})
			.join("");
	};

	function render(d) {
		const c = d.sites.connection;
		body.html(
			`<div class="row">` +
				tile(__("Active sites"), d.sites.active, null) +
				tile(__("Sites online"), c.Online, { label: `${c.Degraded} degraded / ${c.Offline} offline`, c: c.Offline ? "red" : c.Degraded ? "orange" : "green" }) +
				tile(__("Active users"), d.users.Active, { label: `${d.users.Suspended} suspended`, c: d.users.Suspended ? "orange" : "gray" }) +
				tile(__("Open alerts"), d.alerts_open.Critical + d.alerts_open.Warning + d.alerts_open.Info, { label: `${d.alerts_open.Critical} critical`, c: d.alerts_open.Critical ? "red" : "green" }) +
				tile(__("Logins (24h)"), d.logins_24h, null) +
				tile(__("Denied logins (24h)"), d.denied_24h, null) +
				tile(__("Assignments active"), d.assignments.Active, { label: `${d.assignments.Failed} failed`, c: d.assignments.Failed ? "red" : "gray" }) +
				tile(__("Provisioning in flight"), d.assignments.Provisioning, null) +
				`</div>` +
				`<div class="frappe-card" style="padding:12px 16px;margin-bottom:12px"><h5>${__("Provisioning requests, last 7 days")}</h5>${bars(d.requests_daily)}
					<div class="small text-muted" style="margin-top:6px">${pill(__("Succeeded"), "green")} ${pill(__("In progress or review"), "orange")} ${pill(__("Failed"), "red")}</div></div>` +
				table(__("Open alerts"), [__("Severity"), __("Alert"), __("Status"), __("Last seen")],
					d.open_alerts.map((a) => [pill(a.severity, sevColor[a.severity]), link("ThinkNXG Alert", a.name, a.title), esc(a.status), esc(a.last_seen)]), __("No open alerts.")) +
				table(__("Sites needing attention"), [__("Site"), __("Connection"), __("Last check")],
					d.attention_sites.map((s) => [link("ThinkNXG Managed Site", s.name, s.display_name || s.name), pill(s.connection_status, connColor[s.connection_status]), esc(s.last_health_check)]), __("All active sites are online.")) +
				table(__("Provisioning needing attention"), [__("Request"), __("Operation"), __("Site"), __("Status"), __("Last error")],
					d.needs_attention_requests.map((r) => [link("ThinkNXG Provisioning Request", r.name), esc(r.operation), esc(r.site), esc(r.status), esc(r.last_error)]), __("Nothing waiting.")) +
				table(__("Recent sign-in activity"), [__("When"), __("Event"), __("User"), __("Site"), __("Note")],
					d.recent_activity.map((a) => [esc(a.timestamp), esc(a.event), esc(a.user), esc(a.site || ""), esc(a.reason)]), __("No activity yet.")) +
				`<div class="small text-muted">${__("Updated")} ${esc(d.generated_at)}</div>`
		);
	}

	function load() {
		frappe.call({ method: "thinknxg_super_admin.api.dashboard.overview", callback: (r) => r.message && render(r.message) });
	}

	page.set_secondary_action(__("Refresh"), load, "refresh");
	frappe.pages["thinknxg-overview"].refresh = load;
	setInterval(() => {
		if (frappe.get_route_str() === "thinknxg-overview" && !document.hidden) load();
	}, 60000);
	load();
};
