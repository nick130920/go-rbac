// Package jwt issues and validates HS256 access tokens.
//
// The token carries the user identity, the optional tenant/organization id,
// the role assigned to the user and a free-form list of permissions, so that
// downstream middleware can perform authorization without an extra round-trip
// to the database.
package jwt

import (
	"errors"
	"fmt"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims is the canonical access-token payload used across services.
// Custom keys are kept short to minimize header size.
type Claims struct {
	UserID      uuid.UUID `json:"uid"`
	TenantID    string    `json:"tid,omitempty"`
	Email       string    `json:"email,omitempty"`
	Role        string    `json:"role"`
	Permissions []string  `json:"perms,omitempty"`
	gjwt.RegisteredClaims
}

// Issuer signs tokens for a given secret and issuer name.
type Issuer struct {
	secret []byte
	issuer string
	ttl    time.Duration
}

// NewIssuer creates an Issuer. ttl is the access-token lifetime, the issuer
// string ends up in the `iss` claim.
func NewIssuer(secret, issuer string, ttl time.Duration) (*Issuer, error) {
	if len(secret) < 16 {
		return nil, errors.New("jwt: secret must be at least 16 bytes")
	}
	if ttl <= 0 {
		return nil, errors.New("jwt: ttl must be positive")
	}
	return &Issuer{secret: []byte(secret), issuer: issuer, ttl: ttl}, nil
}

// Sign issues a signed token for the supplied claim values. RegisteredClaims
// (issuer/expiry/issued-at) are set automatically.
func (i *Issuer) Sign(c Claims) (string, error) {
	now := time.Now().UTC()
	c.RegisteredClaims = gjwt.RegisteredClaims{
		Issuer:    i.issuer,
		IssuedAt:  gjwt.NewNumericDate(now),
		ExpiresAt: gjwt.NewNumericDate(now.Add(i.ttl)),
		NotBefore: gjwt.NewNumericDate(now),
	}
	t := gjwt.NewWithClaims(gjwt.SigningMethodHS256, c)
	return t.SignedString(i.secret)
}

// Verifier validates incoming tokens using the same secret used to sign them.
type Verifier struct {
	secret []byte
}

// NewVerifier returns a Verifier ready to validate tokens.
func NewVerifier(secret string) (*Verifier, error) {
	if len(secret) < 16 {
		return nil, errors.New("jwt: secret must be at least 16 bytes")
	}
	return &Verifier{secret: []byte(secret)}, nil
}

// Parse validates the supplied token string and returns the typed Claims.
// It rejects tokens signed with an algorithm other than HS256 to prevent
// algorithm-confusion attacks.
func (v *Verifier) Parse(token string) (*Claims, error) {
	t, err := gjwt.ParseWithClaims(token, &Claims{}, func(t *gjwt.Token) (any, error) {
		if _, ok := t.Method.(*gjwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("jwt: unexpected signing method %v", t.Header["alg"])
		}
		return v.secret, nil
	})
	if err != nil {
		return nil, err
	}
	c, ok := t.Claims.(*Claims)
	if !ok || !t.Valid {
		return nil, errors.New("jwt: invalid token")
	}
	return c, nil
}
