// This helper files generates a bunch of ed25519 keys to be used by the test
// runners. This is done such that the signatures stay stable when the metadata
// is regenerated.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/theupdateframework/go-tuf/data"
)

var expirationDate = time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC)

func main() {
	rolenames := []string{
		"root",
		"snapshot",
		"targets",
		"timestamp",
	}

	roles := make(map[string][][]*data.PrivateKey)

	for _, name := range rolenames {
		keys := [][]*data.PrivateKey{}

		for i := 0; i < 2; i++ {
			signer, err := keys.GenerateEd25519Key()
			assertNoError(err)
			keys = append(keys, []*data.PrivateKey{signer})
		}

		roles[name] = keys
	}

	s, err := json.MarshalIndent(&roles, "", "    ")
	assertNoError(err)

	ioutil.WriteFile("keys.json", []byte(s), 0644)
}

func assertNoError(err error) {
	if err != nil {
		panic(fmt.Sprintf("assertion failed: %s", err))
	}
}
