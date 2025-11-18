package auth

import (
	"context"
	"fmt"
	"github/hovanhoa/go-vc-auth/vault"
)

type ProviderOption struct {
	SignerAddress string
	Config        map[string]any
}

func (o *ProviderOption) WithSignerAddress(address string) {
	o.SignerAddress = address
}

func (o *ProviderOption) WithConfig(config map[string]any) {
	o.Config = config
}

// Provider defines the signing capability used by the auth service.
// Sign should take an arbitrary payload and return the signed token bytes.
type Provider interface {
	Sign(payload []byte, options *ProviderOption) ([]byte, error)
}

// VaultProvider is the default provider implementation that uses Vault for signing.
type VaultProvider struct {
	vault *vault.Vault
}

// NewVaultProvider creates a new VaultProvider instance.
// It connects to Vault using the provided address and token.
func NewVaultProvider(address, token string, maxRetries ...int) *VaultProvider {
	retries := 3
	if len(maxRetries) > 0 && maxRetries[0] >= 0 {
		retries = maxRetries[0]
	}

	return &VaultProvider{
		vault: vault.NewVault(address, token, retries),
	}
}

// Sign implements the Provider interface.
// It stores the private key in Vault (if not already stored), then signs the payload using Vault.
func (v *VaultProvider) Sign(payload []byte, options *ProviderOption) ([]byte, error) {
	if options.SignerAddress == "" {
		return nil, fmt.Errorf("signer address is required")
	}

	return v.vault.SignMessage(context.Background(), payload, options.SignerAddress)
}
