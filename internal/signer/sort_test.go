package signer_test

import (
	"encoding/json"
	"reflect"
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
	return nil, nil
}

func (s *mockSigner) UnmarshalPrivateKey(key *data.PrivateKey) error {
	panic("not implemented")
	return nil
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
	return nil, nil
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

	sorted := []keys.Signer{
		s4, s1, s5, s2, s3,
	}

	if !reflect.DeepEqual(s, sorted) {
		t.Errorf("Signers incorrectly sorted: got %+v, want %+v", s, sorted)
	}
}
