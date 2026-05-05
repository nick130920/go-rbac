# Migrating `fintech-backend` to go-rbac

`fintech-backend` is a Gin + GORM service. Today it carries
`pkg/auth/jwt.go` with hand-rolled HS256 helpers and per-handler role
checks. This guide replaces that code with `go-rbac`.

## Step 1 &mdash; Add the dependency

```bash
cd fintech-backend
go get github.com/nick130920/go-rbac@latest
```

## Step 2 &mdash; Replace `pkg/auth`

```go
// pkg/auth/jwt.go
package auth

import (
	"time"

	"github.com/google/uuid"
	gorbacjwt "github.com/nick130920/go-rbac/jwt"
)

type TokenIssuer struct{ inner *gorbacjwt.Issuer }

func NewTokenIssuer(secret string, ttl time.Duration) (*TokenIssuer, error) {
	i, err := gorbacjwt.NewIssuer(secret, "fintech-backend", ttl)
	if err != nil {
		return nil, err
	}
	return &TokenIssuer{inner: i}, nil
}

func (t *TokenIssuer) Issue(userID uuid.UUID, role string, perms ...string) (string, error) {
	return t.inner.Sign(gorbacjwt.Claims{
		UserID:      userID,
		Role:        role,
		Permissions: perms,
	})
}
```

## Step 3 &mdash; Wire the middleware into Gin

```go
// internal/app/app.go
import (
	"github.com/gin-gonic/gin"

	"github.com/nick130920/go-rbac/httpauth/ginmw"
	"github.com/nick130920/go-rbac/jwt"
	"github.com/nick130920/go-rbac/rbac"
)

verifier, _ := jwt.NewVerifier(cfg.JWTSecret)

policy := rbac.NewPolicy().
	GrantRole("admin", "*").
	GrantRole("user", "expenses:read", "expenses:write", "budget:read").
	GrantRole("readonly", "expenses:read", "budget:read")
ac := rbac.New(policy)

api := router.Group("/api/v1", ginmw.Authenticator(verifier))
api.GET("/expenses", expenseHandler.List)
api.POST("/expenses",
	ginmw.RequirePermission(ac, "expenses:write"),
	expenseHandler.Create,
)
api.DELETE("/expenses/:id",
	ginmw.RequireRole("admin"),
	expenseHandler.Delete,
)
```

## Step 4 &mdash; Read the identity inside handlers

```go
import "github.com/nick130920/go-rbac/httpauth"

func (h *ExpenseHandler) Create(c *gin.Context) {
	id, _ := httpauth.IdentityFromContext(c.Request.Context())
	c.JSON(201, gin.H{"created_by": id.UserID})
}
```

## Step 5 &mdash; Cleanup

Delete the legacy `pkg/auth/jwt.go` content (the wrapper above is the only
file you keep) and the per-handler role checks; the middleware now owns
authorization.
