// Package internal contains private helper functions and models needed in client and server
package internal

// TokenOptions contains fields that will be passed to the Attestation Service TokenOptions field.
// These fields are used to customize several claims in the token from the Attestation service.
type TokenOptions struct {
	Audience            string                   `json:"audience"`
	Nonces              []string                 `json:"nonces"`
	TokenType           string                   `json:"token_type"`
	PrincipalTagOptions *AWSPrincipalTagsOptions `json:"aws_principal_tag_options"`
}

type AWSPrincipalTagsOptions struct {
	AllowedPrincipalTags *AllowedPrincipalTags `json:"allowed_principal_tags"`
}

type AllowedPrincipalTags struct {
	ContainerImageSignatures *ContainerImageSignatures `json:"container_image_signatures"`
}

type ContainerImageSignatures struct {
	KeyIds []string `json:"key_ids"`
}
