package internal

import "github.com/google/uuid"

var (
	// SvsmVtpmServiceUUID is the UUID representation of SvsmVtpmServiceGUID.
	SvsmVtpmServiceUUID = uuid.MustParse(SvsmVtpmServiceGUID)
)

// SvsmVtpmServiceGUID is the service_guid for attesting the SVSM VTPM service.
// Specified by SVSM reference (AMD document 58019)
const SvsmVtpmServiceGUID = "c476f1eb-0123-45a5-9641-b4e7dde5bfe3"
