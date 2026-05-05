package jwt_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nick130920/go-rbac/jwt"
)

const testSecret = "test-secret-with-enough-length"

func TestIssuerVerifierRoundtrip(t *testing.T) {
	iss, err := jwt.NewIssuer(testSecret, "tests", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ver, err := jwt.NewVerifier(testSecret)
	if err != nil {
		t.Fatal(err)
	}

	uid := uuid.New()
	token, err := iss.Sign(jwt.Claims{
		UserID:      uid,
		TenantID:    "t1",
		Email:       "x@y.io",
		Role:        "hr",
		Permissions: []string{"workers:read"},
	})
	if err != nil {
		t.Fatal(err)
	}

	c, err := ver.Parse(token)
	if err != nil {
		t.Fatal(err)
	}
	if c.UserID != uid || c.Role != "hr" || c.TenantID != "t1" {
		t.Fatalf("unexpected claims: %+v", c)
	}
}

func TestVerifierRejectsTampered(t *testing.T) {
	iss, _ := jwt.NewIssuer(testSecret, "tests", 5*time.Minute)
	ver, _ := jwt.NewVerifier("different-secret-but-long-enough")
	tok, _ := iss.Sign(jwt.Claims{UserID: uuid.New(), Role: "admin"})
	if _, err := ver.Parse(tok); err == nil {
		t.Fatal("expected verifier to reject token signed with another secret")
	}
}

func TestIssuerRejectsShortSecret(t *testing.T) {
	if _, err := jwt.NewIssuer("short", "tests", time.Minute); err == nil {
		t.Fatal("expected error for short secret")
	}
}
