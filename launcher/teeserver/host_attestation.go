package teeserver

import (
	"encoding/base64"

	attestationpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"
	"google.golang.org/protobuf/proto"
)

const hostAttestationTemplateBinaryPBBase64 = "Kv8BCvwBEggAAAAAAAAAARoOAcEABAALIgIAEgAAAAgilQH/VENHgBQAIgAL52BDci1L0Zb74bhT7aPGFz1s0buKrZvB7cDsJIleLpQAIF0bYMwuAUWnxZSllAR1oinYt+bajeakF1Z4Nuhj/6Z6AAAAAAnWSv0AAAABAAAAAAAAAAAGeMKkFwAiAAssQ4SzvCj56IsUHI3+08X0E13jEcIEhHLVDysp4ACPKwAAAAgAAAAAAAAAASpIABgACwAgcdfYkbJh8b/CQYm9c2AFBdQd8i08QA8CQg/ucvdF0l8AIB7Ecpr5a2lQ+X7BEL2wNVAvdzsshB2KdeuTSA59eVmsIt0JCvgCCAsSJAgREiD//////////////////////////////////////////xIkCBISIO+GOAhAx9Np9il7l6to3KAkOv1Rqke0vWA+LBgz3RtCEiQIFRIg//////////////////////////////////////////8SJAgAEiAvJZ3HUVdDoQTyCzPoYYJY8gocvQHjfajnITLiRqPGnBqRAf9UQ0eAGAAiAAvnYENyLUvRlvvhuFPto8YXPWzRu4qtm8HtwOwkiV4ulAAgXRtgzC4BRafFlKWUBHWiKdi35tqN5qQXVng26GP/pnoAAAAACdZH6AAAAAEAAAAAAAAAAAZ4wqQXAAAAAQALAwEAJgAguqrVudYkIVHcETvyt27/oOaEYYpxnEXkQ0oCT3x2ThkiSAAYAAsAIHNZw60haVYb2VPmZaxuc/Bj0paA+14pmZOEQYruKQBOACByiZm1TfX+TphktBUgMpr99Nm/fW70I9pZSUCSCg7iwxIYZHVtbXlfcGNjbGllbnRfZXZlbnRfbG9nGhpkdW1teV9jZWxfbGF1bmNoX2V2ZW50X2xvZyKpBhKmBgqAAgEAAAABAAAAAAgAAJ9AGH46p1X5AAAAAAAAAAAAAAAAOkCBBSc3qVUEAAAABAKXBAAAAAAGAEAAAAAAAAAAAAD0JfNo3Bu+LmjsHL/LhEMHP1XTkXCRPBr8wAkB3KrkSOdgQ3ItS9GW++G4U+2jxhc9bNG7iq2bwe3A7CSJXi6UfaS7pgXkJOn4j3uGalz63UsYF2D228E7nIlPfKGGetSAFxbCQF2jU1zQBd7dkxYRfMwBzzVb2aW+/2NiJgb+twDfO1NhLvnQnyS+GKn8dn7Sws4xifyTpsSnbFQja7mW0t7yd7DKxZtN0tGsNqt3ltbhZpcCPLycY4z8l1eaXv8SoAQBAAAACwAAAAAGAABmrbvBRyJNxgAAAAAAAAAAAAAAADpAgQUnN6lVBAAAAAQClwQAAAAABgBAAAAAAAAAAAAA4++yicHdAIpeosTh6ar0RrgSBX8RcIi7HOAPseoaFrc/Y4Hoz8foJD4YdthDterYJcJWnRRpRA1ggf8n7UDyyZSanntAHE277l80odqD4YJUbQEF9B2Y5YpQt2Y4gWAwo5YRngxUtGCwZz7u5YOAfAfWvaypyxBL0jOYVL+zjHYBAAAACQAAAAAFAAAMYNgxY1BQUOvpHGD/P93lAAAAAAxg2DEQ3eXULTZa5jnH4fo6QIEFJzepVQQAgAAEApcEbA/MVFvLj4zaBYSnyJpD2URn3ciyHrSI9CtepCZ1uBMnTTBHLc0HNXlhXEhtAALRYggcVshhL6vRkNRh2hrrwE9KGYHASac0+jPdfxkGzSQBZd4bJl3xNAaT+aK6Xwm4N2c3Q90WUysSAAem7H0svKHXdmK9rWQpcKer6byWNcv3hd8TGQZCmB28vSOWwITHLqBeLn8QCu53p3SYd/JfmPQsd1XiRjNhx3b1mzuuSPyMjguFSt/FKxJ7WEQQIhPixfxxwkNxepTxoz6fgBuMeJKdAeMNZoWStI4nOuk93S8Y64cVJpRCPMjna2cdegxAQnKX1ypujCZZIv1B8oUHQomhp9fF3WX/Hz1afff3QwHTAytmXm6aIXiKeJK1bIHPEiCrq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urqwoQSE9TVF9BVFRFU1RBVElPTg=="

func dummyHostAttestation(_ []byte) *attestationpb.HostAttestation {
	evidence := &attestationpb.HostAttestation{}
	b, err := base64.StdEncoding.DecodeString(hostAttestationTemplateBinaryPBBase64)
	if err != nil {
		panic("failed to decode host attestation template binarypb: " + err.Error())
	}
	if err := proto.Unmarshal(b, evidence); err != nil {
		panic("failed to unmarshal host attestation template: " + err.Error())
	}
	return evidence
}
