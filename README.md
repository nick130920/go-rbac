# go-rbac

Reusable Go library for **JWT-based authentication** and **role / permission
authorization**, framework-agnostic at the core with thin adapters for
[`chi`](https://github.com/go-chi/chi) and [`gin`](https://github.com/gin-gonic/gin).

The same primitives power `hases-api`, `fintech-backend`, and any other
service in the catalog so each project gets the same security baseline for
free.

## Install

```bash
go get github.com/nick130920/go-rbac
```

## Packages

| Import path | Purpose |
|---|---|
| `github.com/nick130920/go-rbac/jwt` | HS256 token issuance and verification with the canonical `Claims` payload. |
| `github.com/nick130920/go-rbac/rbac` | `Identity`, `Policy` and `AccessControl` for role and permission checks. |
| `github.com/nick130920/go-rbac/httpauth` | `net/http`-level Authenticator middleware and `RequireRole` / `RequirePermission` guards. |
| `github.com/nick130920/go-rbac/httpauth/chimw` | Chi-flavored aliases. |
| `github.com/nick130920/go-rbac/httpauth/ginmw` | Gin-flavored aliases. |

## Quick start

### 1. Issue a token on login

```go
import (
    "time"

    "github.com/google/uuid"
    "github.com/nick130920/go-rbac/jwt"
)

iss, _ := jwt.NewIssuer(os.Getenv("JWT_SECRET"), "hases-api", 8*time.Hour)

token, _ := iss.Sign(jwt.Claims{
    UserID:      uuid.MustParse("a4b1..."),
    TenantID:    "hases",
    Email:       "ana@hases.co",
    Role:        "hr",
    Permissions: []string{"workers:read", "workers:write"},
})
```

### 2. Declare a Policy once at boot time

```go
import "github.com/nick130920/go-rbac/rbac"

policy := rbac.NewPolicy().
    GrantRole("admin", "*").
    GrantRole("hr", "workers:read", "workers:write", "vacancies:publish").
    GrantRole("hiring_manager", "vacancies:publish", "applications:read").
    GrantRole("evaluator", "applications:read", "interviews:write").
    GrantRole("worker", "self:read", "documents:upload")

ac := rbac.New(policy)
```

### 3. Wire the middleware

#### chi (the way `hases-api` should look)

```go
import (
    "github.com/go-chi/chi/v5"

    "github.com/nick130920/go-rbac/httpauth"
    "github.com/nick130920/go-rbac/httpauth/chimw"
    "github.com/nick130920/go-rbac/jwt"
)

verifier, _ := jwt.NewVerifier(os.Getenv("JWT_SECRET"))
authn := httpauth.NewAuthenticator(verifier)

r := chi.NewRouter()
r.Group(func(r chi.Router) {
    r.Use(chimw.Authenticator(authn))

    r.With(chimw.RequireRole("admin")...).
        Get("/admin/users", listUsers)

    r.With(chimw.RequirePermission(ac, "vacancies:publish")...).
        Post("/vacancies", createVacancy)
})
```

#### Gin (`fintech-backend` style)

```go
import (
    "github.com/gin-gonic/gin"

    "github.com/nick130920/go-rbac/httpauth/ginmw"
    "github.com/nick130920/go-rbac/jwt"
)

verifier, _ := jwt.NewVerifier(os.Getenv("JWT_SECRET"))
authorized := router.Group("/api/v1", ginmw.Authenticator(verifier))
authorized.GET("/me", meHandler)
authorized.POST(
    "/expenses",
    ginmw.RequirePermission(ac, "expenses:write"),
    createExpense,
)
```

### 4. Read the identity inside handlers

```go
import "github.com/nick130920/go-rbac/httpauth"

func listUsers(w http.ResponseWriter, r *http.Request) {
    id, _ := httpauth.IdentityFromContext(r.Context())
    log.Printf("user %s (role=%s) listing users", id.UserID, id.Role)
}
```

## Migrating `hases-api`

`hases-api/internal/auth/jwt.go` and `internal/adapters/http/middleware.go`
are functionally equivalent to a small subset of `go-rbac`. Replace them
with this library:

1. **Delete** `internal/auth/jwt.go`, `internal/adapters/http/middleware.go`.
2. **Add** the dependency:
   ```bash
   go get github.com/nick130920/go-rbac@latest
   ```
3. **Replace** the per-handler `RequireRoles(r, "admin")` calls with the
   declarative chi middleware shown above. Keep the existing claim layout by
   mapping your domain `Role` constants to `rbac.Identity.Role` values.

A drop-in adapter that mimics the legacy signature lives at
`examples/chi-app/legacy_compat.go` to make the migration incremental.

## License

Apache-2.0.
