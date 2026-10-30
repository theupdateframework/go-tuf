package updater

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

type memoryMetadataStore struct {
	docs  map[string][]byte
	err   error
	reads int
}

func (s *memoryMetadataStore) Load(role string) ([]byte, error) {
	s.reads++
	data, ok := s.docs[role]
	if !ok {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(data), nil
}

func (s *memoryMetadataStore) Persist(role string, data []byte) error {
	if s.err != nil {
		return s.err
	}
	s.docs[role] = bytes.Clone(data)
	return nil
}

func TestMetadataStoreRefreshAndPersistenceFailure(t *testing.T) {
	if err := loadOrResetTrustedRootMetadata(); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadUpdaterConfig()
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryMetadataStore{docs: make(map[string][]byte)}
	cfg.MetadataStore = store
	u, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Refresh(); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"root", "timestamp", "snapshot", "targets"} {
		if len(store.docs[role]) == 0 {
			t.Fatalf("store did not persist %s", role)
		}
	}
	u, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Refresh(); err != nil {
		t.Fatal(err)
	}
	if store.reads == 0 {
		t.Fatal("store loads bypassed")
	}
	store.err = errors.New("disk unavailable")
	if _, err := New(cfg); !errors.Is(err, store.err) {
		t.Fatalf("persist error not returned: %v", err)
	}
}
