"""Structural checks of every DocType JSON, runnable without a bench.

The allowed field types, DocField keys, DocType keys and DocPerm keys below were extracted
from the Frappe v16 source tree (core/doctype/{docfield,doctype,docperm}). Regenerate them
when upgrading Frappe.
"""

import json
import unittest
from pathlib import Path

PKG = "thinknxg_super_admin"
ROOT = Path(__file__).resolve().parents[1]

FIELD_TYPES = set(
	[
		"Autocomplete",
		"Attach",
		"Attach Image",
		"Attachment Gallery",
		"Barcode",
		"Button",
		"Check",
		"Code",
		"Color",
		"Column Break",
		"Currency",
		"Data",
		"Date",
		"Datetime",
		"Duration",
		"Dynamic Link",
		"Float",
		"Fold",
		"Geolocation",
		"Heading",
		"HTML",
		"HTML Editor",
		"Icon",
		"Image",
		"Int",
		"JSON",
		"Link",
		"Long Text",
		"Markdown Editor",
		"Password",
		"Percent",
		"Phone",
		"Read Only",
		"Rating",
		"Section Break",
		"Select",
		"Signature",
		"Small Text",
		"Tab Break",
		"Table",
		"Table MultiSelect",
		"Text",
		"Text Editor",
		"Time",
		"Vue Component",
	]
)
NAMING_RULES = set(
	[
		"",
		"Set by user",
		"Autoincrement",
		"By fieldname",
		'By "Naming Series" field',
		"Expression",
		"Expression (old style)",
		"Random",
		"UUID",
		"By script",
	]
)
DOCFIELD_KEYS = set(
	[
		"alignment",
		"allow_bulk_edit",
		"allow_in_quick_entry",
		"allow_on_submit",
		"bold",
		"button_color",
		"collapsible",
		"collapsible_depends_on",
		"column_break_13",
		"column_break_18",
		"column_break_22",
		"column_break_28",
		"column_break_35",
		"column_break_38",
		"column_break_6",
		"columns",
		"constraints_section",
		"default",
		"defaults_section",
		"depends_on",
		"description",
		"display",
		"documentation_url",
		"fetch_from",
		"fetch_if_empty",
		"fieldname",
		"fieldtype",
		"hidden",
		"hide_border",
		"hide_days",
		"hide_seconds",
		"ignore_user_permissions",
		"ignore_xss_filter",
		"in_filter",
		"in_global_search",
		"in_import_template",
		"in_list_view",
		"in_preview",
		"in_standard_filter",
		"is_virtual",
		"label",
		"label_and_type",
		"length",
		"link_filters",
		"list__search_settings_section",
		"make_attachment_public",
		"mandatory_depends_on",
		"mask",
		"max_height",
		"no_copy",
		"non_negative",
		"not_nullable",
		"oldfieldname",
		"oldfieldtype",
		"options",
		"permissions",
		"permlevel",
		"placeholder",
		"precision",
		"print_hide",
		"print_hide_if_no_value",
		"print_width",
		"read_only",
		"read_only_depends_on",
		"remember_last_selected_value",
		"report_hide",
		"reqd",
		"search_index",
		"set_only_once",
		"show_dashboard",
		"show_description_on_click",
		"show_on_timeline",
		"sort_options",
		"sticky",
		"translatable",
		"unique",
		"visibility_section",
		"width",
	]
)
DOCTYPE_KEYS = set(
	[
		"actions",
		"actions_section",
		"advanced",
		"allow_auto_repeat",
		"allow_bulk_edit",
		"allow_copy",
		"allow_events_in_timeline",
		"allow_guest_to_view",
		"allow_import",
		"allow_rename",
		"autoname",
		"beta",
		"cb01",
		"color",
		"column_break_23",
		"column_break_29",
		"column_break_51",
		"column_break_nexu",
		"connections_tab",
		"custom",
		"default_email_template",
		"default_print_format",
		"default_view",
		"deprecated",
		"description",
		"document_states_section",
		"document_type",
		"documentation",
		"editable_grid",
		"email_append_to",
		"email_settings_sb",
		"enable_upload_first_workflow",
		"engine",
		"fields",
		"fields_section",
		"fields_tab",
		"force_re_route_to_default_view",
		"form_builder",
		"form_builder_tab",
		"form_settings_section",
		"grid_page_length",
		"has_web_view",
		"hide_toolbar",
		"icon",
		"image_field",
		"in_create",
		"index_web_pages_for_search",
		"is_calendar_and_gantt",
		"is_published_field",
		"is_submittable",
		"is_tree",
		"is_virtual",
		"issingle",
		"istable",
		"link_display_mode",
		"links",
		"links_section",
		"make_attachments_public",
		"max_attachments",
		"migration_hash",
		"module",
		"naming_rule",
		"nsm_parent_field",
		"permissions",
		"permissions_tab",
		"protect_attached_files",
		"queue_in_background",
		"quick_entry",
		"read_only",
		"recipient_account_field",
		"restrict_to_domain",
		"route",
		"row_format",
		"rows_threshold_for_grid_search",
		"sb0",
		"sb1",
		"search_fields",
		"sender_field",
		"sender_name_field",
		"settings_tab",
		"show_image_in_link",
		"show_name_in_global_search",
		"show_preview_popup",
		"show_title_field_in_link",
		"sort_field",
		"sort_order",
		"states",
		"subject_field",
		"timeline_field",
		"title_field",
		"track_changes",
		"track_seen",
		"track_views",
		"translated_doctype",
		"view_settings",
		"web_view",
		"website_search_field",
		"doctype",
		"creation",
		"modified",
		"modified_by",
		"owner",
		"name",
		"idx",
		"docstatus",
		"field_order",
		"fields",
		"permissions",
		"links",
		"actions",
		"states",
	]
)
DOCPERM_KEYS = set(
	[
		"additional_permissions",
		"amend",
		"cancel",
		"column_break_19",
		"column_break_2",
		"column_break_8",
		"create",
		"delete",
		"email",
		"export",
		"if_owner",
		"import",
		"mask",
		"permlevel",
		"print",
		"read",
		"report",
		"role",
		"role_and_level",
		"section_break_4",
		"select",
		"share",
		"submit",
		"write",
	]
)
STANDARD_LINKS = {"User", "Role", "Language"}
LAYOUT = {"Section Break", "Column Break", "Tab Break"}
NO_DATA = LAYOUT | {"Table", "Table MultiSelect", "HTML", "Button", "Heading"}


def load_all():
	out = {}
	for path in ROOT.glob("*/doctype/*/*.json"):
		data = json.loads(path.read_text())
		out[data["name"]] = (path, data)
	return out


class TestDocTypeSchema(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		cls.docs = load_all()

	def test_found_doctypes(self):
		self.assertGreaterEqual(len(self.docs), 24)

	def test_file_layout_matches_name(self):
		for name, (path, _data) in self.docs.items():
			scrubbed = name.lower().replace(" ", "_")
			self.assertEqual(path.stem, scrubbed, name)
			self.assertEqual(path.parent.name, scrubbed, name)
			self.assertTrue((path.parent / "__init__.py").exists(), name)
			if "thinknxg_super_admin" == "thinknxg_super_admin":
				self.assertTrue((path.parent / f"{scrubbed}.py").exists(), f"controller missing for {name}")

	def test_doctype_keys_and_module(self):
		for name, (_, d) in self.docs.items():
			self.assertLessEqual(set(d) - DOCTYPE_KEYS, set(), name)
			self.assertEqual(d["module"], "thinkNXG Super Admin", name)
			if d.get("naming_rule"):
				self.assertIn(d["naming_rule"], NAMING_RULES, name)

	def test_fields(self):
		for name, (_, d) in self.docs.items():
			names = [f["fieldname"] for f in d["fields"]]
			self.assertEqual(len(names), len(set(names)), f"duplicate fieldname in {name}")
			self.assertEqual(d["field_order"], names, name)
			for f in d["fields"]:
				where = f"{name}.{f['fieldname']}"
				self.assertLessEqual(set(f) - DOCFIELD_KEYS, set(), where)
				self.assertIn(f["fieldtype"], FIELD_TYPES, where)
				if f["fieldtype"] not in LAYOUT:
					self.assertIn("label", f, where)
				if f.get("unique") or f.get("search_index"):
					self.assertNotIn(f["fieldtype"], NO_DATA, where)
				if f.get("unique") and d.get("istable"):
					self.fail(f"unique field in child table {where}")
				if f["fieldtype"] in ("Link", "Table"):
					target = f.get("options")
					self.assertTrue(target in self.docs or target in STANDARD_LINKS, f"{where} -> {target}")
				if f["fieldtype"] == "Table":
					self.assertTrue(self.docs[f["options"]][1].get("istable"), where)
				if f["fieldtype"] == "Select":
					opts = f["options"].split("\n")
					self.assertEqual(len(opts), len(set(opts)), where)
					if f.get("default"):
						self.assertIn(f["default"], opts, where)
				if f.get("fetch_from"):
					link, _, _ = f["fetch_from"].partition(".")
					self.assertIn(link, names, where)

	def test_title_and_search_fields_exist(self):
		for name, (_, d) in self.docs.items():
			names = {f["fieldname"] for f in d["fields"]}
			if d.get("title_field"):
				self.assertIn(d["title_field"], names, name)
			for s in filter(None, (d.get("search_fields") or "").split(",")):
				self.assertIn(s.strip(), names, name)

	def test_autoname_field_exists_and_is_unique(self):
		for name, (_, d) in self.docs.items():
			auto = d.get("autoname") or ""
			if auto.startswith("field:"):
				fname = auto[6:]
				match = [f for f in d["fields"] if f["fieldname"] == fname]
				self.assertTrue(match, name)
				self.assertTrue(match[0].get("reqd") or match[0].get("unique"), name)

	def test_permissions(self):
		for name, (_, d) in self.docs.items():
			if d.get("istable"):
				self.assertEqual(d["permissions"], [], name)
				continue
			self.assertTrue(d["permissions"], f"{name} has no permissions")
			for p in d["permissions"]:
				self.assertLessEqual(set(p) - DOCPERM_KEYS, set(), name)
				self.assertNotIn(p["role"], ("All", "Guest"), name)

	def test_log_doctypes_are_read_only_for_everyone(self):
		for name in [
			"ThinkNXG Audit Log",
			"ThinkNXG Provisioning Log",
			"ThinkNXG Site Health Log",
			"ThinkNXG Login Activity",
			"ThinkNXG Provisioning Request",
			"ThinkNXG Alert",
		]:
			for p in self.docs[name][1]["permissions"]:
				for flag in ("write", "create", "delete"):
					self.assertFalse(p.get(flag), f"{name}: {p['role']} has {flag}")

	def test_normal_users_have_no_central_permissions(self):
		if PKG != "thinknxg_super_admin":
			return
		allowed = {"System Manager", "thinkNXG Super Admin", "thinkNXG Org Admin", "thinkNXG Auditor"}
		for name, (_, d) in self.docs.items():
			for p in d["permissions"]:
				self.assertIn(p["role"], allowed, name)


if __name__ == "__main__":
	unittest.main()
