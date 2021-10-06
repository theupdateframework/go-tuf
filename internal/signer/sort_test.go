package signer_test

import (
	"crypto"
	"reflect"
	"sort"
	"testing"

	"github.com/theupdateframework/go-tuf/internal/signer"
	"github.com/theupdateframework/go-tuf/sign"
)

type mockSigner struct {
	ids []string

	crypto.Signer
}

func (s *mockSigner) IDs() []string {
	return s.ids
}

func (s *mockSigner) ContainsID(id string) bool {
	for _, keyid := range s.IDs() {
		if id == keyid {
			return true
		}
	}
	return false
}

func (s *mockSigner) Type() string {
	return "type"
}

func (s *mockSigner) Scheme() string {
	return "scheme"
}

func TestSignerSortByIDs(t *testing.T) {
	s1 := &mockSigner{
		ids: []string{"c", "b", "a"},
	}
	s2 := &mockSigner{
		ids: []string{"a", "d", "z"},
	}
	s3 := &mockSigner{
		ids: []string{"x", "y"},
	}
	s4 := &mockSigner{
		ids: []string{"x", "y", "z"},
	}
	s5 := &mockSigner{
		ids: []string{"z", "z", "z"},
	}

	s := []sign.Signer{
		s4, s5, s3, s2, s1,
	}

	sort.Sort(signer.ByIDs(s))

	sorted := []sign.Signer{
		s1, s2, s3, s4, s5,
	}

	if !reflect.DeepEqual(s, sorted) {
		t.Errorf("Signers incorrectly sorted: got %+v, want %+v", s, sorted)
	}
}
