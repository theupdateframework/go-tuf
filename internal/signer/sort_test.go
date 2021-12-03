package signer_test

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/internal/signer"
	"github.com/theupdateframework/go-tuf/pkg/keys"
)

type mockSigner struct {
	value json.RawMessage
}

func (s *mockSigner) MarshalPrivateKey() (*data.PrivateKey, error) {
	panic("not implemented")
}

func (s *mockSigner) UnmarshalPrivateKey(key *data.PrivateKey) error {
	panic("not implemented")
}

func (s *mockSigner) PublicData() *data.PublicKey {
	return &data.PublicKey{
		Type:       "mock",
		Scheme:     "mock",
		Algorithms: []string{"mock"},
		Value:      s.value,
	}
}
func (s *mockSigner) SignMessage(message []byte) ([]byte, error) {
	panic("not implemented")
}

func TestSignerSortByIDs(t *testing.T) {
	s1 := &mockSigner{
		value: json.RawMessage(`{"mock": 1}`),
	}
	s2 := &mockSigner{
		value: json.RawMessage(`{"mock": 2}`),
	}
	s3 := &mockSigner{
		value: json.RawMessage(`{"mock": 3}`),
	}
	s4 := &mockSigner{
		value: json.RawMessage(`{"mock": 4}`),
	}
	s5 := &mockSigner{
		value: json.RawMessage(`{"mock": 5}`),
	}

	s := []keys.Signer{
		s1, s2, s3, s4, s5,
	}

	sort.Sort(signer.ByIDs(s))

	signerIDs := []string{}

	for i, signer := range s {
		ids := signer.PublicData().IDs()
		if len(ids) != 1 {
			t.Errorf("Signer %v IDs %v should have length 1", i, ids)
		}
		signerIDs = append(signerIDs, ids[0])
	}

	if !sort.StringsAreSorted(signerIDs) {
		t.Errorf("Signers incorrectly sorted: %+v", signerIDs)
	}
}
