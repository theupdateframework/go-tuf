package util

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"io"

	"github.com/flynn/go-tuf/data"
)

type BytesReadCloser struct {
	*bytes.Reader
}

func (b BytesReadCloser) Close() error {
	return nil
}

func FileMetaEqual(actual data.FileMeta, expected data.FileMeta) bool {
	if actual.Length != expected.Length {
		return false
	}
	for typ, hash := range expected.Hashes {
		if !hmac.Equal(actual.Hashes[typ], hash) {
			return false
		}
	}
	return true
}

func GenerateFileMeta(r io.Reader) (data.FileMeta, error) {
	h := sha512.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return data.FileMeta{}, err
	}
	return data.FileMeta{
		Length: n,
		Hashes: map[string]data.HexBytes{"sha512": h.Sum(nil)},
	}, nil
}
