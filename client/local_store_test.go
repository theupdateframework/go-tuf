package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeleteMeta(t *testing.T) {
	l := MemoryLocalStore()
	assert.Equal(t, l.SetMeta("root.json", []byte(`
  {
	  "signed": {},
	  "signatures": {},
  }
  `)), nil)
	m, err := l.GetMeta()
	assert.Equal(t, err, nil)
	if _, ok := m["root.json"]; !ok {
		t.Fatalf("Expected metadata not found!")
	}
	l.DeleteMeta("root.json")
	if _, ok := m["root.json"]; ok {
		t.Fatalf("Metadata is not deleted!")
	}
}
