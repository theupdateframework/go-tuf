package client

import (
	"encoding/json"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/storage"
)

func FileLocalStore(path string) (LocalStore, error) {
	fd, err := storage.OpenFile(path, false)
	if err != nil {
		return nil, err
	}

	db, err := leveldb.Open(fd, nil)
	return &fileLocalStore{db: db}, err
}

type fileLocalStore struct {
	db *leveldb.DB
}

func (f *fileLocalStore) GetMeta() (map[string]json.RawMessage, error) {
	meta := make(map[string]json.RawMessage)
	db_itr := f.db.NewIterator(nil, nil)
	for db_itr.Next() {
		vcopy := make([]byte, len(db_itr.Value()))
		copy(vcopy, db_itr.Value())
		meta[string(db_itr.Key())] = vcopy
	}
	db_itr.Release()
	return meta, db_itr.Error()
}

func (f *fileLocalStore) SetMeta(name string, meta json.RawMessage) error {
	return f.db.Put([]byte(name), []byte(meta), nil)
}
