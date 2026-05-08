package teeserver

import (
	"encoding/base64"

	attestationpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"
	"google.golang.org/protobuf/proto"
)

const hostAttestationTemplateBinaryPBBase64 = "KvUBCvIBGg4BwQAFAAsiBCwQAAAACCKVAf9UQ0eAFAAiAAsJnWa+pjgIVq20nwAw7EYzlGmSumoLw+TagILE4c0YTQAgXRtgzC4BRafFlKWUBHWiKdi35tqN5qQXVng26GP/pnoAAAAAADFAigAAAAEAAAAAAAAAAAZ4wvNjACIAC+d99cacIbMKueZHJbga6dk1pAKwEfAj9OhWE5AaKi0fAAAACAAAAAAAAAACKkgAGAALACBZCtUk5HjffwjgwPXB9gt2PBCHVOzX7zLsasU8O516CAAgD79LU/yV/Qp7ph2elHAG1Rtd59REwupKDsrAVG/+u60i3QkK+AIICxIkCBUSIP//////////////////////////////////////////EiQIERIg//////////////////////////////////////////8SJAgAEiAvJZ3HUVdDoQTyCzPoYYJY8gocvQHjfajnITLiRqPGnBIkCBISIO+GOAhAx9Np9il7l6to3KAkOv1Rqke0vWA+LBgz3RtCGpEB/1RDR4AYACIACwmdZr6mOAhWrbSfADDsRjOUaZK6agvD5NqAgsThzRhNACBdG2DMLgFFp8WUpZQEdaIp2Lfm2o3mpBdWeDboY/+megAAAAAAMT27AAAAAQAAAAAAAAAABnjC82MAAAABAAsDAQAmACC6qtW51iQhUdwRO/K3bv+g5oRhinGcReRDSgJPfHZOGSJIABgACwAgGtVYirgdkY9UOhVQIJAF80JyEnGP/ZXNQtpy3bG4ZOMAIJWr7HjAml6RUILtEfjZyzJ1sznQ2uAq5NxT21gcixVFEhhkdW1teV9wY2NsaWVudF9ldmVudF9sb2caGmR1bW15X2NlbF9sYXVuY2hfZXZlbnRfbG9nIqkGEqYGCoACAQAAAAEAAAAACAAAn0AYfobOBFsAAAAAAAAAAAAAAAA6QIEFJzepVQQAAAAEApcEAAAAAAYAQAAAAAAAAAAAAGO3+h5yzVuCebPmRUjNC5ERwx8MJMijzxjIE97KCL+tCZ1mvqY4CFattJ8AMOxGM5RpkrpqC8Pk2oCCxOHNGE1cpjzMBlrWaMOlT87PeSeC7mMxVk3uW2Nzn9B6XnMA7ufAeHvX6H1pfOiekTn875Ubm4i5E5NWqgvvhRHsHErczxb0hDWKUVSNKx/1RSied2VnKYPDqR2anSsMQqh9ivRElKCWocRN464iTIPi+3h5apHJOoEamrE7/zLXjHxZ4hKgBAEAAAALAAAAAAYAAGatu8FHIk3GAAAAAAAAAAAAAAAAOkCBBSc3qVUEAAAABAKXBAAAAAAGAEAAAAAAAAAAAADj77KJwd0Ail6ixOHpqvRGuBIFfxFwiLsc4A+x6hoWtz9jgejPx+gkPhh22EO16tglwladFGlEDWCB/yftQPLJlJqee0AcTbvuXzSh2oPhglRtAQX0HZjlilC3ZjiBYDCjlhGeDFS0YLBnPu7lg4B8B9a9rKnLEEvSM5hUv7OMdgEAAAAJAAAAAAUAAAxg2DFjUFBQ6+kcYP8/3eUAAAAADGDYMRDd5dQtNlrmOcfh+jpAgQUnN6lVBACAAAQClwRsD8xUW8uPjNoFhKfImkPZRGfdyLIetIj0K16kJnW4EydNMEctzQc1eWFcSG0AAtFiCBxWyGEvq9GQ1GHaGuvAT0oZgcBJpzT6M91/GQbNJAFl3hsmXfE0BpP5orpfCbg3ZzdD3RZTKxIAB6bsfSy8odd2Yr2tZClwp6vpvJY1y/eF3xMZBkKYHby9I5bAhMcuoF4ufxAK7nendJh38l+Y9Cx3VeJGM2HHdvWbO65I/IyOC4VK38UrEntYRBAiE+LF/HHCQ3F6lPGjPp+AG4x4kp0B4w1mhZK0jic66T3dLxjrhxUmlEI8yOdrZx16DEBCcpfXKm6MJlki/UHyhQdCiaGn18XdZf8fPVp99/dDAdMDK2ZebpoheIp4krVsgc8SIKurq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urChBIT1NUX0FUVEVTVEFUSU9O"

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
