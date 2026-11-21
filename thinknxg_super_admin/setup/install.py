import frappe

from thinknxg_super_admin.setup.indexes import ensure_indexes
from thinknxg_super_admin.setup.keys import ensure_central_keys
from thinknxg_super_admin.setup.roles import ROLES


def after_install():
	ensure_roles()
	ensure_indexes()
	ensure_central_keys()


def after_migrate():
	ensure_roles()
	ensure_indexes()
	ensure_central_keys()


def ensure_roles():
	"""Create missing roles. Never modifies an existing role, so local edits survive migrate."""
	for role_name, options in ROLES.items():
		if frappe.db.exists("Role", role_name):
			continue
		frappe.get_doc({"doctype": "Role", "role_name": role_name, **options}).insert(ignore_permissions=True)
	frappe.db.commit()
