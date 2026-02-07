package workload_service

import (
	"github.com/google/uuid"
)

// mockBindingKeyGen implements BindingKeyGenerator for testing.
type mockBindingKeyGen struct {
	uuid   uuid.UUID
	pubKey []byte
	err    error
}

func (m *mockBindingKeyGen) GenerateBindingKeypair() (uuid.UUID, []byte, error) {
	return m.uuid, m.pubKey, m.err
}

// mockKEMKeyGen implements KEMKeyGenerator for testing.
type mockKEMKeyGen struct {
	uuid           uuid.UUID
	pubKey         []byte
	err            error
	receivedPubKey []byte
}

func (m *mockKEMKeyGen) GenerateKEMKeypair(bindingPubKey []byte) (uuid.UUID, []byte, error) {
	m.receivedPubKey = bindingPubKey
	return m.uuid, m.pubKey, m.err
}
