package client

import (
	"encoding/json"
	"sync"
)

// ConcurrentLocalStore provides a LocalStore over an existing LocalStore
// implementation that is safe for concurrent access.
type ConcurrentLocalStore struct {
	mtx   sync.RWMutex
	store LocalStore
}

// NewConcurrentLocalStore returns a wrapped LocalStore that is safe for
// concurrent access.
func NewConcurrentLocalStore(s LocalStore) *ConcurrentLocalStore {
	return &ConcurrentLocalStore{
		store: s,
	}
}

// GetMeta returns all known targets.
func (c *ConcurrentLocalStore) GetMeta() (map[string]json.RawMessage, error) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()
	return c.store.GetMeta()
}

// SetMeta updates the lcoal store with a new target.
func (c *ConcurrentLocalStore) SetMeta(name string, meta json.RawMessage) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.store.SetMeta(name, meta)
}

// DeleteMeta remves a target from the cache.
func (c *ConcurrentLocalStore) DeleteMeta(name string) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.store.DeleteMeta(name)
}

// Close closes the local store.
func (c *ConcurrentLocalStore) Close() error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.store.Close()
}
