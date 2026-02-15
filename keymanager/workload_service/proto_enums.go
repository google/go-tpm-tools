package workload_service

// These enum values mirror the proto definitions in PROTOS.md and are used by
// the WSD JSON API contract.

// KemAlgorithm represents the requested KEM algorithm.
type KemAlgorithm int32

const (
	KemAlgorithmUnspecified           KemAlgorithm = 0
	KemAlgorithmDHKEMX25519HKDFSHA256 KemAlgorithm = 1
)

// KeyProtectionMechanism represents the requested key protection backend.
type KeyProtectionMechanism int32

const (
	KeyProtectionMechanismDefault KeyProtectionMechanism = 1
	KeyProtectionMechanismVM      KeyProtectionMechanism = 2
)
