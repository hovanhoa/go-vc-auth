package auth

import (
	"context"
	"encoding/json"
	"errors"

	vcdto "github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

type Auth interface {
	// CreateToken creates a new VP token with a list of VCs.
	CreateToken(ctx context.Context, vpContents vp.PresentationContents) (string, error)

	// VerifyToken verifies a VP token with a list of VCs.
	VerifyToken(ctx context.Context, token string) ([]VcClaims, error)
}

type auth struct {
	provider Provider
}

func NewAuth(p Provider, didUrl string) Auth {
	vp.Init(didUrl)
	vc.Init(didUrl)
	return &auth{
		provider: p,
	}
}

// NewAuthWithDefaultProvider creates a new Auth instance with a default VaultProvider.
// It connects to Vault using the provided address and token.
func NewAuthWithDefaultProvider(vaultAddress, vaultToken, didUrl string, maxRetries ...int) Auth {
	provider := NewVaultProvider(vaultAddress, vaultToken, maxRetries...)
	return NewAuth(provider, didUrl)
}

func (a *auth) CreateToken(ctx context.Context, vpContents vp.PresentationContents) (string, error) {
	vpPresentation, err := vp.NewJWTPresentation(vpContents)
	if err != nil {
		return "", err
	}

	signData, err := vpPresentation.GetSigningInput()
	if err != nil {
		return "", err
	}

	signature, err := a.provider.Sign(signData)
	if err != nil {
		return "", err
	}

	err = vpPresentation.AddCustomProof(&vcdto.Proof{
		Signature: signature,
	})
	if err != nil {
		return "", err
	}

	document, err := vpPresentation.Serialize()
	if err != nil {
		return "", err
	}

	documentBytes, err := json.Marshal(document)
	if err != nil {
		return "", err
	}

	return string(documentBytes), nil

}

func (a *auth) VerifyToken(ctx context.Context, token string) ([]VcClaims, error) {
	vpPresentation, err := vp.ParseJWTPresentation(token, vp.WithVerifyProof(), vp.WithVCValidation())
	if err != nil {
		return nil, err
	}

	// Get VP contents
	vpContentsBytes, err := vpPresentation.GetContents()
	if err != nil {
		return nil, err
	}

	// Parse VP contents as JSON
	var vpData map[string]interface{}
	if err := json.Unmarshal(vpContentsBytes, &vpData); err != nil {
		return nil, err
	}

	// Extract verifiableCredential array
	vcsRaw, ok := vpData["verifiableCredential"]
	if !ok {
		return nil, errors.New("no verifiableCredential found in VP")
	}

	vcsArray, ok := vcsRaw.([]interface{})
	if !ok {
		return nil, errors.New("verifiableCredential is not an array")
	}

	// Parse each VC and extract CredentialContents
	var vcClaimsList []VcClaims
	for _, vcItem := range vcsArray {
		var credential vc.Credential
		var err error

		credential, err = vc.ParseCredential([]byte(vcItem.(string)))

		if err != nil {
			return nil, err
		}

		// Get credential contents
		credContentsBytes, err := credential.GetContents()
		if err != nil {
			return nil, err
		}

		// Parse credential contents to VC Claims
		var vcClaims VcClaims
		if err := json.Unmarshal(credContentsBytes, &vcClaims); err != nil {
			return nil, err
		}

		vcClaimsList = append(vcClaimsList, vcClaims)
	}

	return vcClaimsList, nil
}
