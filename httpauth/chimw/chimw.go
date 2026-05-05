// Package chimw provides idiomatic helpers to wire go-rbac into a chi router.
// All helpers return chi.Middleware functions, so they compose naturally with
// chi.Router.Use and chi.Router.With.
package chimw

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/nick130920/go-rbac/httpauth"
	"github.com/nick130920/go-rbac/rbac"
)

// Authenticator returns a chi-friendly middleware that authenticates the
// caller using the supplied httpauth.Authenticator.
func Authenticator(a *httpauth.Authenticator) func(http.Handler) http.Handler {
	return a.Middleware
}

// RequirePermission is the chi alias of httpauth.RequirePermission.
func RequirePermission(ac *rbac.AccessControl, permission string) chi.Middlewares {
	return chi.Middlewares{httpauth.RequirePermission(ac, permission)}
}

// RequireRole is the chi alias of httpauth.RequireRole.
func RequireRole(roles ...string) chi.Middlewares {
	return chi.Middlewares{httpauth.RequireRole(roles...)}
}
