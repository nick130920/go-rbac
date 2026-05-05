package rbac_test

import (
	"testing"

	"github.com/nick130920/go-rbac/rbac"
)

func TestAccessControl(t *testing.T) {
	policy := rbac.NewPolicy().
		GrantRole("admin", "*").
		GrantRole("hr", "workers:read", "workers:write")
	ac := rbac.New(policy)

	cases := []struct {
		name string
		id   rbac.Identity
		perm string
		want bool
	}{
		{"admin wildcard", rbac.Identity{Role: "admin"}, "anything", true},
		{"hr granted", rbac.Identity{Role: "hr"}, "workers:read", true},
		{"hr denied", rbac.Identity{Role: "hr"}, "billing:write", false},
		{"explicit perm beats role", rbac.Identity{Role: "worker", Permissions: []string{"workers:write"}}, "workers:write", true},
		{"unknown role denied", rbac.Identity{Role: "ghost"}, "workers:read", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ac.Allow(tc.id, tc.perm)
			if got != tc.want {
				t.Fatalf("Allow(%+v, %q) = %v, want %v", tc.id, tc.perm, got, tc.want)
			}
		})
	}
}

func TestIdentityHasRole(t *testing.T) {
	id := rbac.Identity{Role: "hr"}
	if !id.HasRole("admin", "hr") {
		t.Fatal("expected hr to match")
	}
	if id.HasRole("admin") {
		t.Fatal("did not expect admin match")
	}
}
