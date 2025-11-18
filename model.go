package auth

import "time"

// CredentialDocument represents credential document.
type CredentialDocument struct {
	Context          []string            `json:"@context"`
	ID               string              `json:"id"`
	Types            []string            `json:"types"`
	Issuer           string              `json:"issuer"`
	ValidFrom        time.Time           `json:"validFrom"`
	ValidUntil       time.Time           `json:"validUntil"`
	CredentialStatus []CredentialStatus  `json:"credentialStatus"`
	Subject          []CredentialSubject `json:"subject"`
	Schemas          []CredentialSchema  `json:"schemas"`
}

// CredentialStatus represents the status field as per W3C Verifiable Credentials.
type CredentialStatus struct {
	ID                   string `json:"id,omitempty"`
	Type                 string `json:"type"`
	StatusPurpose        string `json:"statusPurpose,omitempty"`
	StatusListIndex      string `json:"statusListIndex,omitempty"`
	StatusListCredential string `json:"statusListCredential,omitempty"`
}

// CredentialSubject represents the subject field as per W3C Verifiable Credentials.
type CredentialSubject struct {
	ID           string         `json:"id"`
	CustomFields map[string]any `json:"customFields"`
}

// CredentialSchema represents the schemas field as per W3C Verifiable Credentials.
type CredentialSchema struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}
