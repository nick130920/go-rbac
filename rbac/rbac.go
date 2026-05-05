// Package rbac implements role-based and permission-based authorization.
//
// The model is intentionally minimal: an Identity holds a single role and a
// set of permissions; an AccessControl evaluates whether an Identity is
// authorized to perform an action.
//
// Permissions are free-form strings such as "workers:read" or
// "vacancies:publish"; roles are short labels like "admin" or "hr".
package rbac

// Identity represents an authenticated principal that wants to perform an
// action. It is created from a JWT claim set or any other authenticated
// source.
type Identity struct {
	UserID      string
	TenantID    string
	Role        string
	Permissions []string
}

// HasRole reports whether the identity matches any of the supplied roles.
func (i Identity) HasRole(roles ...string) bool {
	for _, r := range roles {
		if i.Role == r {
			return true
		}
	}
	return false
}

// HasPermission reports whether the identity carries the given permission.
// A permission of "*" wildcards everything.
func (i Identity) HasPermission(p string) bool {
	for _, granted := range i.Permissions {
		if granted == "*" || granted == p {
			return true
		}
	}
	return false
}

// Policy is the set of rules that grant access. A Policy is composed of:
//   - A static role -> permissions map (used to expand the user role into the
//     permissions it implies, when permissions are not embedded in the JWT).
//   - A list of "deny" rules evaluated before allow rules.
type Policy struct {
	rolePerms map[string][]string
}

// NewPolicy creates an empty policy.
func NewPolicy() *Policy {
	return &Policy{rolePerms: map[string][]string{}}
}

// GrantRole binds a role to a list of permissions. Subsequent calls for the
// same role override the previous binding.
func (p *Policy) GrantRole(role string, permissions ...string) *Policy {
	p.rolePerms[role] = append([]string(nil), permissions...)
	return p
}

// PermissionsFor returns the permissions granted to a role, or nil if the
// role is unknown.
func (p *Policy) PermissionsFor(role string) []string {
	return p.rolePerms[role]
}

// AccessControl combines a Policy with an Identity to produce concrete
// authorization decisions. Use New(...) to construct it.
type AccessControl struct {
	policy *Policy
}

// New returns an AccessControl bound to the given policy.
func New(p *Policy) *AccessControl {
	return &AccessControl{policy: p}
}

// Allow returns true when the identity is authorized for the given permission.
// The check first consults the embedded permissions and, if none match, falls
// back to the role -> permissions map declared in the policy.
func (a *AccessControl) Allow(id Identity, permission string) bool {
	if id.HasPermission(permission) {
		return true
	}
	for _, granted := range a.policy.PermissionsFor(id.Role) {
		if granted == "*" || granted == permission {
			return true
		}
	}
	return false
}

// AllowAny is a convenience wrapper that returns true if the identity is
// authorized for at least one of the supplied permissions.
func (a *AccessControl) AllowAny(id Identity, permissions ...string) bool {
	for _, p := range permissions {
		if a.Allow(id, p) {
			return true
		}
	}
	return false
}

// AllowAll returns true only when every permission is satisfied.
func (a *AccessControl) AllowAll(id Identity, permissions ...string) bool {
	for _, p := range permissions {
		if !a.Allow(id, p) {
			return false
		}
	}
	return true
}
