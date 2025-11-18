package auth_test

import (
	auth "github/hovanhoa/go-vc-auth"

	"testing"
)

// testProvider is a simple in-memory Provider implementation for tests.
type testProvider struct{}

func (p *testProvider) Sign(payload, privateKey []byte) ([]byte, error) {
	// TODO: Implement the simple signing logic here
	// Return the signed payload
	return payload, nil
}

// TestNewAuth ensures NewAuth returns a non-nil Auth implementation.
func TestNewAuth(t *testing.T) {
	p := &testProvider{}
	a := auth.NewAuth(p)
	if a == nil {
		t.Fatalf("expected non-nil Auth")
	}
}

// TODO: Add more tests here for auth functionality
