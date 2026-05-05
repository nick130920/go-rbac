// Example chi-app shows go-rbac wired to a chi router. Run with:
//
//	JWT_SECRET=please-change-this-secret go run ./examples/chi-app
//
// Then call:
//
//	# issue a token (admin)
//	curl -s localhost:8080/auth/login -d '{"email":"admin@x.io"}'
//	# call a protected endpoint
//	curl -s -H "Authorization: Bearer <TOKEN>" localhost:8080/admin/ping
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/nick130920/go-rbac/httpauth"
	"github.com/nick130920/go-rbac/httpauth/chimw"
	"github.com/nick130920/go-rbac/jwt"
	"github.com/nick130920/go-rbac/rbac"
)

func main() {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "please-change-this-secret"
	}

	issuer, err := jwt.NewIssuer(secret, "go-rbac-example", 1*time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	verifier, err := jwt.NewVerifier(secret)
	if err != nil {
		log.Fatal(err)
	}

	policy := rbac.NewPolicy().
		GrantRole("admin", "*").
		GrantRole("hr", "workers:read", "workers:write").
		GrantRole("worker", "self:read")
	ac := rbac.New(policy)
	authn := httpauth.NewAuthenticator(verifier)

	r := chi.NewRouter()

	r.Post("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Email string `json:"email"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		role := "worker"
		if body.Email == "admin@x.io" {
			role = "admin"
		}
		token, _ := issuer.Sign(jwt.Claims{
			UserID: uuid.New(),
			Email:  body.Email,
			Role:   role,
		})
		writeJSON(w, http.StatusOK, map[string]string{"token": token})
	})

	r.Group(func(r chi.Router) {
		r.Use(chimw.Authenticator(authn))

		r.With(chimw.RequireRole("admin")...).
			Get("/admin/ping", func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, map[string]string{"ok": "admin"})
			})

		r.With(chimw.RequirePermission(ac, "workers:read")...).
			Get("/workers", func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, []string{"alice", "bob"})
			})
	})

	addr := ":8080"
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, r))
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
