package tuf

import "encoding/json"

func MemoryLocalStore() LocalStore {
	var m memoryLocalStore
	return &m
}

type memoryLocalStore map[string]json.RawMessage

func (m *memoryLocalStore) GetMeta() (map[string]json.RawMessage, error) {
	return *m, nil
}

func (m *memoryLocalStore) SetMeta(meta map[string]json.RawMessage) error {
	*m = meta
	return nil
}
