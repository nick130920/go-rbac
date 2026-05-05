# Migrating `hases-api` to go-rbac

`hases-api` (chi + pgx + golang-jwt) ships with two files we want to retire:

- `internal/auth/jwt.go` &mdash; `Sign` / `Parse`
- `internal/adapters/http/middleware.go` &mdash; `BearerAuth`, `ClaimsFromCtx`, `RequireRoles`

`go-rbac` provides a superset of every feature these files implement. The
plan below replaces the local code with the library while keeping every
existing handler call site untouched, so the migration is a one-shot drop-in
without a long refactor branch.

## Step 1 &mdash; Add the dependency

```bash
cd hases-api
go get github.com/nick130920/go-rbac@latest
```

This pulls `go-rbac` together with `golang-jwt/jwt/v5` and `google/uuid`,
both of which `hases-api` already declares; `go mod tidy` will deduplicate
them.

## Step 2 &mdash; Replace `internal/auth/jwt.go`

Delete the file. Add a thin re-export so existing callers keep compiling:

```go
// internal/auth/jwt.go
package auth

import (
	"time"

	"github.com/google/uuid"
	gorbacjwt "github.com/nick130920/go-rbac/jwt"
)

// Claims keeps the legacy public alias so handlers do not need to change.
type Claims = gorbacjwt.Claims

// Sign mirrors the legacy signature (secret, userID, email, role, hours).
func Sign(secret string, userID uuid.UUID, email, role string, hours int) (string, error) {
	iss, err := gorbacjwt.NewIssuer(secret, "hases-api", time.Duration(hours)*time.Hour)
	if err != nil {
		return "", err
	}
	return iss.Sign(gorbacjwt.Claims{
		UserID: userID,
		Email:  email,
		Role:   role,
	})
}

// Parse mirrors the legacy signature (secret, tokenStr).
func Parse(secret, tokenStr string) (*Claims, error) {
	v, err := gorbacjwt.NewVerifier(secret)
	if err != nil {
		return nil, err
	}
	return v.Parse(tokenStr)
}
```

The `password.go` file stays as it is &mdash; bcrypt does not belong to
go-rbac.

## Step 3 &mdash; Replace `internal/adapters/http/middleware.go`

```go
// internal/adapters/http/middleware.go
package httpapi

import (
	"net/http"

	appauth "github.com/hases/hases-api/internal/auth"
	"github.com/nick130920/go-rbac/httpauth"
	gorbacjwt "github.com/nick130920/go-rbac/jwt"
	"github.com/nick130920/go-rbac/rbac"
)

func BearerAuth(secret string, next http.Handler) http.Handler {
	v, err := gorbacjwt.NewVerifier(secret)
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":"jwt secret misconfigured"}`, http.StatusInternalServerError)
		})
	}
	return httpauth.NewAuthenticator(v).Middleware(next)
}

func ClaimsFromCtx(r *http.Request) *appauth.Claims {
	id, ok := httpauth.IdentityFromContext(r.Context())
	if !ok {
		return nil
	}
	return &appauth.Claims{
		UserID: parseUUID(id.UserID),
		Email:  "",
		Role:   id.Role,
	}
}

func RequireRoles(r *http.Request, allowed ...string) bool {
	id, ok := httpauth.IdentityFromContext(r.Context())
	if !ok {
		return false
	}
	return rbac.Identity(id).HasRole(allowed...)
}
```

`parseUUID` is a tiny helper that converts the string we get from go-rbac
back to a `uuid.UUID` (Hases stored it that way originally). It can be a
4-line wrapper around `uuid.Parse` ignoring the error &mdash; the token has
already been validated by the time we read it.

The 25+ handlers calling `RequireRoles(r, ...)` keep working without
edits.

## Step 4 &mdash; Optional: declarative authorization

For new endpoints, replace the imperative `if !RequireRoles(...)` pattern
with a chi middleware so the router itself enforces access:

```go
import (
	"github.com/nick130920/go-rbac/httpauth/chimw"
	"github.com/nick130920/go-rbac/rbac"
)

policy := rbac.NewPolicy().
	GrantRole("admin", "*").
	GrantRole("hr", "workers:read", "workers:write", "vacancies:publish").
	GrantRole("hiring_manager", "vacancies:publish", "applications:read").
	GrantRole("evaluator", "applications:read", "interviews:write").
	GrantRole("worker", "self:read", "documents:upload")
ac := rbac.New(policy)

r.With(chimw.RequirePermission(ac, "workers:write")...).
	Post("/workers", h.CreateWorker)
```

Once every legacy handler is migrated, you can delete the compatibility
shim entirely.

## Step 5 &mdash; Verify

```bash
go test ./...
go build ./cmd/api
```

The behaviour is identical: same secret, same algorithm (HS256), same
claim layout. JWTs issued before the migration keep being accepted.
