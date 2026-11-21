"""Role definitions for the central site. Single source of truth for role names."""

SUPER_ADMIN = "thinkNXG Super Admin"
ORG_ADMIN = "thinkNXG Org Admin"
AUDITOR = "thinkNXG Auditor"

# role name -> desk access. Normal end users deliberately get NO role and NO Desk access:
# the user dashboard is served by whitelisted methods that scope results to the caller.
ROLES = {
	SUPER_ADMIN: {"desk_access": 1},
	ORG_ADMIN: {"desk_access": 1},
	AUDITOR: {"desk_access": 1},
}
