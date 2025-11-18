package auth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"

	vcdto "github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

type Auth interface {
	// CreateToken creates a new VP token with a list of VCs.
	CreateToken(ctx context.Context, vcsJwt []string, holderDid string) (string, error)

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

// extractAddressFromDID extracts the Ethereum address from a DID string.
// It returns the substring after the last colon.
// Example: "did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce" -> "0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce"
func extractAddressFromDID(did string) string {
	lastColonIndex := strings.LastIndex(did, ":")
	if lastColonIndex == -1 {
		return did // Return original string if no colon found
	}
	return did[lastColonIndex+1:]
}

// CreateToken creates a new VP token with a list of VCs.
// It returns the VP token as a JWT string.
// Example:
// ```
// token, err := auth.CreateToken(context.Background(), []string{vcJwt1, vcJwt2}, "did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce")
// ```
// @param ctx context.Context - The context for the request.
// @param vcsJwt []string - The list of VCs as JWT strings.
// @param holderDid string - The DID of the holder.
// @return string - The VP token as a JWT string.
// @return error - The error if the token creation fails.
func (a *auth) CreateToken(ctx context.Context, vcsJwt []string, holderDid string) (string, error) {
	vcs := make([]vc.Credential, len(vcsJwt))
	for i, vcJwt := range vcsJwt {
		vc, err := vc.ParseCredential([]byte(vcJwt))
		if err != nil {
			return "", err
		}
		vcs[i] = vc
	}

	vpContents := vp.PresentationContents{
		Holder:                holderDid,
		Types:                 []string{"VerifiablePresentation"},
		VerifiableCredentials: vcs,
		Context:               []interface{}{"https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"},
	}

	vpPresentation, err := vp.NewJWTPresentation(vpContents)
	if err != nil {
		return "", err
	}

	signData, err := vpPresentation.GetSigningInput()
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(signData)

	signature, err := a.provider.Sign(hash[:], &ProviderOption{
		SignerAddress: extractAddressFromDID(vpContents.Holder),
	})

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

// VerifyToken verifies a VP token with a list of VCs.
// It returns the list of VC claims.
// Example:
// ```
// claims, err := auth.VerifyToken(context.Background(), token)
//
//	if err != nil {
//		return nil, err
//	}
//
// ```
// @param ctx context.Context - The context for the request.
// @param token string - The VP token as a JWT string.
// @return []VcClaims - The list of VC claims.
// @return error - The error if the token verification fails.
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

		var credContents map[string]interface{}
		if err := json.Unmarshal(credContentsBytes, &credContents); err != nil {
			return nil, err
		}

		vcClaims := VcClaims{
			Issuer:  credContents["issuer"].(string),
			Subject: credContents["credentialSubject"].(map[string]interface{}),
		}

		vcClaimsList = append(vcClaimsList, vcClaims)
	}

	return vcClaimsList, nil
}
