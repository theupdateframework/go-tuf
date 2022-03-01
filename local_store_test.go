package tuf

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/pkg/keys"
)

func TestLocalStoreSigners(t *testing.T) {
	tmpdir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		os.RemoveAll(tmpdir)
	}()

	stores := map[string]LocalStore{
		"MemoryStore":     MemoryStore(nil, nil),
		"FileSystemStore": FileSystemStore(tmpdir, nil),
	}

	for name, store := range stores {
		t.Run(name, func(t *testing.T) {
			signers, err := store.GetSigners("abc")
			assert.NoError(t, err)
			assert.Equal(t, len(signers), 0)

			// Add two signers to role "a".
			aSigner1, err := keys.GenerateEd25519Key()
			assert.NoError(t, err)
			err = store.SaveSigner("a", aSigner1)
			assert.NoError(t, err)

			aSigner2, err := keys.GenerateEd25519Key()
			assert.NoError(t, err)
			err = store.SaveSigner("a", aSigner2)
			assert.NoError(t, err)

			// Add one signer to role "b".
			bSigner, err := keys.GenerateEd25519Key()
			assert.NoError(t, err)
			err = store.SaveSigner("b", bSigner)
			assert.NoError(t, err)

			// Add to b again to test deduplication.
			err = store.SaveSigner("b", bSigner)
			assert.NoError(t, err)

			signers, err = store.GetSigners("a")
			assert.NoError(t, err)
			assert.ElementsMatch(t, []keys.Signer{aSigner1, aSigner2}, signers)

			signers, err = store.GetSigners("b")
			assert.NoError(t, err)
			assert.ElementsMatch(t, []keys.Signer{bSigner}, signers)

			a1KeyIDs := aSigner1.PublicData().IDs()
			a2KeyIDs := aSigner2.PublicData().IDs()
			bKeyIDs := bSigner.PublicData().IDs()

			assert.Equal(t, []keys.Signer{aSigner1}, store.SignersForKeyIDs(a1KeyIDs))
			assert.Equal(t, []keys.Signer{aSigner2}, store.SignersForKeyIDs(a2KeyIDs))
			assert.ElementsMatch(t, []keys.Signer{aSigner1, aSigner2}, store.SignersForKeyIDs(append(a1KeyIDs, a2KeyIDs...)))
			assert.Equal(t, []keys.Signer{bSigner}, store.SignersForKeyIDs(bKeyIDs))
		})
	}
}
