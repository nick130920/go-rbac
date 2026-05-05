// Package httpauth glues package jwt and package rbac to the standard
// net/http request pipeline. Framework-specific helpers (chi, gin, ...) live
// in sub-packages and reuse the primitives defined here.
package httpauth

import (
	"context"
	"net/http"
	"strings"

	"github.com/nick130920/go-rbac/jwt"
	"github.com/nick130920/go-rbac/rbac"
)

type ctxKey int

const identityKey ctxKey = 1

// IdentityFromContext returns the Identity stored by Authenticator, or false
// when the request is anonymous.
func IdentityFromContext(ctx context.Context) (rbac.Identity, bool) {
	v, ok := ctx.Value(identityKey).(rbac.Identity)
	return v, ok
}

// WithIdentity returns a copy of ctx with the supplied identity attached.
// Useful in tests or when authenticating through a different mechanism.
func WithIdentity(ctx context.Context, id rbac.Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

// Authenticator parses the Bearer token in the Authorization header, builds
// an Identity from the JWT claims and stores it in the request context. When
// no token is present or the token is invalid, the supplied OnError handler
// is invoked.
type Authenticator struct {
	Verifier *jwt.Verifier
	OnError  func(w http.ResponseWriter, r *http.Request, err error)
}

// NewAuthenticator returns an Authenticator with sane defaults: a 401 JSON
// response on errors.
func NewAuthenticator(v *jwt.Verifier) *Authenticator {
	return &Authenticator{
		Verifier: v,
		OnError: func(w http.ResponseWriter, _ *http.Request, _ error) {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		},
	}
}

// Middleware returns a net/http middleware that requires a valid Bearer
// token. Successful requests get an Identity attached to their context.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := bearerToken(r)
		if err != nil {
			a.OnError(w, r, err)
			return
		}
		claims, err := a.Verifier.Parse(raw)
		if err != nil {
			a.OnError(w, r, err)
			return
		}
		id := rbac.Identity{
			UserID:      claims.UserID.String(),
			TenantID:    claims.TenantID,
			Role:        claims.Role,
			Permissions: claims.Permissions,
		}
		next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
	})
}

// RequirePermission returns a middleware that allows the request only when
// the authenticated identity has the supplied permission.
func RequirePermission(ac *rbac.AccessControl, permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, ok := IdentityFromContext(r.Context())
			if !ok || !ac.Allow(id, permission) {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole returns a middleware that allows the request only when the
// authenticated identity carries any of the supplied roles.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, ok := IdentityFromContext(r.Context())
			if !ok || !id.HasRole(roles...) {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func bearerToken(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", errAuthRequired
	}
	const prefix = "bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", errMalformedHeader
	}
	return strings.TrimSpace(h[len(prefix):]), nil
}

var (
	errAuthRequired    = httpError("missing Authorization header")
	errMalformedHeader = httpError("malformed Authorization header")
)

type httpError string

func (e httpError) Error() string { return string(e) }
