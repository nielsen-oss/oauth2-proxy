package providers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"github.com/coreos/go-oidc"
	"github.com/dgrijalva/jwt-go"
	"net/url"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/stretchr/testify/assert"
)

func TestRefresh(t *testing.T) {
	p := &ProviderData{}

	expires := time.Now().Add(time.Duration(-11) * time.Minute)
	refreshed, err := p.RefreshSessionIfNeeded(context.Background(), &sessions.SessionState{
		ExpiresOn: &expires,
	})
	assert.Equal(t, false, refreshed)
	assert.Equal(t, nil, err)
}

func TestAcrValuesNotConfigured(t *testing.T) {
	p := &ProviderData{
		LoginURL: &url.URL{
			Scheme: "http",
			Host:   "my.test.idp",
			Path:   "/oauth/authorize",
		},
	}

	result := p.GetLoginURL("https://my.test.app/oauth", "")
	assert.NotContains(t, result, "acr_values")
}

func TestAcrValuesConfigured(t *testing.T) {
	p := &ProviderData{
		LoginURL: &url.URL{
			Scheme: "http",
			Host:   "my.test.idp",
			Path:   "/oauth/authorize",
		},
		AcrValues: "testValue",
	}

	result := p.GetLoginURL("https://my.test.app/oauth", "")
	assert.Contains(t, result, "acr_values=testValue")
}

func TestCreateSessionStateFromBearerToken(t *testing.T) {
	minimalIDToken := jwt.StandardClaims{
		Audience:  "asdf1234",
		ExpiresAt: time.Now().Add(time.Duration(5) * time.Minute).Unix(),
		Id:        "id-some-id",
		IssuedAt:  time.Now().Unix(),
		Issuer:    "https://issuer.example.com",
		NotBefore: 0,
		Subject:   "123456789",
	}
	// From oidc_test.go
	verifier := oidc.NewVerifier(
		"https://issuer.example.com",
		fakeKeySetStub{},
		&oidc.Config{ClientID: "asdf1234"},
	)

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	rawIDToken, _ := jwt.NewWithClaims(jwt.SigningMethodRS256, minimalIDToken).SignedString(key)
	idToken, err := verifier.Verify(context.Background(), rawIDToken)

	session, err := (*ProviderData)(nil).CreateSessionStateFromBearerToken(context.Background(), rawIDToken, idToken)

	assert.Equal(t, nil, err)
	assert.Equal(t, rawIDToken, session.AccessToken)
	assert.Equal(t, rawIDToken, session.IDToken)
	assert.Equal(t, "", session.RefreshToken)
	assert.Equal(t, "123456789", session.Email)
	assert.Equal(t, "123456789", session.User)
	assert.Equal(t, "", session.PreferredUsername)
}
