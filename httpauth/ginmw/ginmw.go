// Package ginmw adapts go-rbac to a Gin router. The Gin dependency is
// declared as optional via build tags so projects that do not use Gin can
// still depend on go-rbac without pulling Gin into their dependency tree.
package ginmw

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/nick130920/go-rbac/httpauth"
	"github.com/nick130920/go-rbac/jwt"
	"github.com/nick130920/go-rbac/rbac"
)

// Authenticator returns Gin middleware that parses the Bearer token and
// stores the resulting Identity both on the request context and on the
// gin.Context under the key "identity".
func Authenticator(v *jwt.Verifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, err := bearerToken(c.Request)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		claims, err := v.Parse(raw)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		id := rbac.Identity{
			UserID:      claims.UserID.String(),
			TenantID:    claims.TenantID,
			Role:        claims.Role,
			Permissions: claims.Permissions,
		}
		c.Request = c.Request.WithContext(httpauth.WithIdentity(c.Request.Context(), id))
		c.Set("identity", id)
		c.Next()
	}
}

// RequirePermission aborts with 403 unless the authenticated identity holds
// the supplied permission.
func RequirePermission(ac *rbac.AccessControl, permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, ok := httpauth.IdentityFromContext(c.Request.Context())
		if !ok || !ac.Allow(id, permission) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.Next()
	}
}

// RequireRole aborts with 403 unless the identity has any of the given roles.
func RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, ok := httpauth.IdentityFromContext(c.Request.Context())
		if !ok || !id.HasRole(roles...) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.Next()
	}
}

func bearerToken(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", errUnauthorized
	}
	const prefix = "bearer "
	if len(h) <= len(prefix) || !equalFold(h[:len(prefix)], prefix) {
		return "", errUnauthorized
	}
	return h[len(prefix):], nil
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

var errUnauthorized = httpError("unauthorized")

type httpError string

func (e httpError) Error() string { return string(e) }
