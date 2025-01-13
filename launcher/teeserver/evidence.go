package teeserver

type tdxEvidence struct {
	CcelAcpiTable     []byte `json:"ccel_table,omitempty"`
	CcelData          []byte `json:"event_log,omitempty"`
	CanonicalEventLog []byte `json:"canonical_event_log"`
	Quote             []byte `json:"quote"`
}

type containerSignature struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

type containerImageSignatures struct {
	KeyIDs []string `json:"key_ids"`
}

type principalTags struct {
	ContainerImageSigs containerImageSignatures `json:"container_image_signatures"`
}

type tokenTypeOptions struct {
	AllowedPrincipalTags principalTags `json:"allowed_principal_tags"`
}

type tokenOptions struct {
	Audience      string           `json:"audience"`
	Nonces        []string         `json:"nonces"`
	TokenType     string           `json:"token_type"`
	TokenTypeOpts tokenTypeOptions `json:"token_type_options"`
}

type confidentialSpaceInfo struct {
	SignedEntities []containerSignature `json:"signed_entities"`
	TokenOpts      tokenOptions         `json:"token_options"`
}

type gcpData struct {
	GcpCredentials    []string              `json:"gcp_credentials"`
	AKCert            []byte                `json:"ak_cert"`
	IntermediateCerts [][]byte              `json:"intermediate_certs"`
	CSInfo            confidentialSpaceInfo `json:"confidential_space_info"`
}

type tokenRequest struct {
	PolicyMatch bool        `json:"policy_must_match"`
	TDX         tdxEvidence `json:"tdx"`
	SigAlg      string      `json:"token_signing_alg"`
	GCP         gcpData     `json:"gcpcs"`
}
