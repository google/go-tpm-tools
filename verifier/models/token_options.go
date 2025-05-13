// Package models contains models needed in client and server
package models

// TokenOptions contains fields that will be passed to the Attestation Service TokenOptions field.
// These fields are used to customize several claims in the token from the Attestation service.
type TokenOptions struct {
	Audience            string                   `json:"audience"`
	Nonces              []string                 `json:"nonces"`
	TokenType           string                   `json:"token_type"`
	PrincipalTagOptions *AWSPrincipalTagsOptions `json:"aws_principal_tag_options"`
}

// AWSPrincipalTagsOptions represents the options for the AWSPrincipalTag token type.
type AWSPrincipalTagsOptions struct {
	AllowedPrincipalTags *AllowedPrincipalTags `json:"allowed_principal_tags"`
}

// AllowedPrincipalTags allows for requestors to configure what principal tags are contained in the
// resulting GCA token.
type AllowedPrincipalTags struct {
	ContainerImageSignatures *ContainerImageSignatures `json:"container_image_signatures"`
}

// ContainerImageSignatures represents the configuration for AllowedPrincipalTags for
// ContainerImageSignature claims
type ContainerImageSignatures struct {
	KeyIDs []string `json:"key_ids"`
}
