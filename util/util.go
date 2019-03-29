package util

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"path"

	"github.com/flynn/go-tuf/data"
)

type ErrWrongLength struct {
	Expected int64
	Actual   int64
}

func (e ErrWrongLength) Error() string {
	return fmt.Sprintf("wrong length, expected %d got %d", e.Expected, e.Actual)
}

type ErrWrongVersion struct {
	Expected int
	Actual   int
}

func (e ErrWrongVersion) Error() string {
	return fmt.Sprintf("wrong version, expected %d got %d", e.Expected, e.Actual)
}

type ErrWrongHash struct {
	Type     string
	Expected data.HexBytes
	Actual   data.HexBytes
}

func (e ErrWrongHash) Error() string {
	return fmt.Sprintf("wrong %s hash, expected %s got %s", e.Type, hex.EncodeToString(e.Expected), hex.EncodeToString(e.Actual))
}

type ErrNoCommonHash struct {
	Expected data.Hashes
	Actual   data.Hashes
}

func (e ErrNoCommonHash) Error() string {
	types := func(a data.Hashes) []string {
		t := make([]string, 0, len(a))
		for typ := range a {
			t = append(t, typ)
		}
		return t
	}
	return fmt.Sprintf("no common hash function, expected one of %s, got %s", types(e.Expected), types(e.Actual))
}

type ErrUnknownHashAlgorithm struct {
	Name string
}

func (e ErrUnknownHashAlgorithm) Error() string {
	return fmt.Sprintf("unknown hash algorithm: %s", e.Name)
}

type PassphraseFunc func(role string, confirm bool) ([]byte, error)

func FileMetaEqual(actual data.FileMeta, expected data.FileMeta) error {
	if actual.Length != expected.Length {
		return ErrWrongLength{expected.Length, actual.Length}
	}
	hashChecked := false
	for typ, hash := range expected.Hashes {
		if h, ok := actual.Hashes[typ]; ok {
			hashChecked = true
			if !hmac.Equal(h, hash) {
				return ErrWrongHash{typ, hash, h}
			}
		}
	}
	if !hashChecked {
		return ErrNoCommonHash{expected.Hashes, actual.Hashes}
	}
	return nil
}

func versionEqual(actual int, expected int) error {
	// FIXME(TUF-0.9) TUF-0.9 does not contain version numbers in the
	// metadata, so we only check them if we received TUF-1.0 compatible
	// metadata.
	if expected != 0 && actual != expected {
		return ErrWrongVersion{expected, actual}
	}
	return nil
}

func SnapshotFileMetaEqual(actual data.SnapshotFileMeta, expected data.SnapshotFileMeta) error {
	if err := FileMetaEqual(actual.FileMeta, expected.FileMeta); err != nil {
		return err
	}

	if err := versionEqual(actual.Version, expected.Version); err != nil {
		return err
	}

	return nil
}

func TargetFileMetaEqual(actual data.TargetFileMeta, expected data.TargetFileMeta) error {
	return FileMetaEqual(actual.FileMeta, expected.FileMeta)
}

func TimestampFileMetaEqual(actual data.TimestampFileMeta, expected data.TimestampFileMeta) error {
	if err := FileMetaEqual(actual.FileMeta, expected.FileMeta); err != nil {
		return err
	}

	if err := versionEqual(actual.Version, expected.Version); err != nil {
		return err
	}

	return nil
}

const defaultHashAlgorithm = "sha512"

func GenerateFileMeta(r io.Reader, hashAlgorithms ...string) (data.FileMeta, error) {
	if len(hashAlgorithms) == 0 {
		hashAlgorithms = []string{defaultHashAlgorithm}
	}
	hashes := make(map[string]hash.Hash, len(hashAlgorithms))
	for _, hashAlgorithm := range hashAlgorithms {
		var h hash.Hash
		switch hashAlgorithm {
		case "sha256":
			h = sha256.New()
		case "sha512":
			h = sha512.New()
		default:
			return data.FileMeta{}, ErrUnknownHashAlgorithm{hashAlgorithm}
		}
		hashes[hashAlgorithm] = h
		r = io.TeeReader(r, h)
	}
	n, err := io.Copy(ioutil.Discard, r)
	if err != nil {
		return data.FileMeta{}, err
	}
	m := data.FileMeta{Length: n, Hashes: make(data.Hashes, len(hashes))}
	for hashAlgorithm, h := range hashes {
		m.Hashes[hashAlgorithm] = h.Sum(nil)
	}
	return m, nil
}

type versionedMeta struct {
	Version int `json:"version"`
}

func generateVersionedFileMeta(r io.Reader, hashAlgorithms ...string) (data.FileMeta, int, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return data.FileMeta{}, 0, err
	}

	m, err := GenerateFileMeta(bytes.NewReader(b), hashAlgorithms...)
	if err != nil {
		return data.FileMeta{}, 0, err
	}

	s := data.Signed{}
	if err := json.Unmarshal(b, &s); err != nil {
		return data.FileMeta{}, 0, err
	}

	vm := versionedMeta{}
	if err := json.Unmarshal(s.Signed, &vm); err != nil {
		return data.FileMeta{}, 0, err
	}

	return m, vm.Version, nil
}

func GenerateSnapshotFileMeta(r io.Reader, hashAlgorithms ...string) (data.SnapshotFileMeta, error) {
	m, v, err := generateVersionedFileMeta(r, hashAlgorithms...)
	if err != nil {
		return data.SnapshotFileMeta{}, err
	}
	return data.SnapshotFileMeta{m, v}, nil
}

func GenerateTargetFileMeta(r io.Reader, hashAlgorithms ...string) (data.TargetFileMeta, error) {
	m, err := GenerateFileMeta(r, hashAlgorithms...)
	if err != nil {
		return data.TargetFileMeta{}, err
	}
	return data.TargetFileMeta{m}, nil
}

func GenerateTimestampFileMeta(r io.Reader, hashAlgorithms ...string) (data.TimestampFileMeta, error) {
	m, v, err := generateVersionedFileMeta(r, hashAlgorithms...)
	if err != nil {
		return data.TimestampFileMeta{}, err
	}
	return data.TimestampFileMeta{m, v}, nil
}

func NormalizeTarget(p string) string {
	return path.Join("/", p)
}

func HashedPaths(p string, hashes data.Hashes) []string {
	paths := make([]string, 0, len(hashes))
	for _, hash := range hashes {
		hashedPath := path.Join(path.Dir(p), hash.String()+"."+path.Base(p))
		paths = append(paths, hashedPath)
	}
	return paths
}

func StringSliceToSet(items []string) map[string]struct{} {
	s := make(map[string]struct{})
	for _, item := range items {
		s[item] = struct{}{}
	}
	return s
}
