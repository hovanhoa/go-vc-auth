package auth

import (
	"context"
)

type Auth interface {
	// CreateToken creates a new VP token with a list of VCs.
	CreateToken(ctx context.Context, vcs []CredentialDocument) (string, error)

	// VerifyToken verifies a VP token with a list of VCs.
	VerifyToken(ctx context.Context, token string) ([]CredentialDocument, error)
}

type auth struct{}

func NewAuth() Auth {
	return &auth{}
}

func (a *auth) CreateToken(ctx context.Context, vcs []CredentialDocument) (string, error) {
	// TODO: Verify the list of VC documents
	// Create a VP token with the list of VC documents
	// Return the VP token
	return "", nil
}

func (a *auth) VerifyToken(ctx context.Context, token string) ([]CredentialDocument, error) {
	// TODO: Add verify VP token logic here
	// Parse the VP token into multiple VC documents
	// Verify each VC document
	// Return the list of verified VC documents
	return nil, nil
}
