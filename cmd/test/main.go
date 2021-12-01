package main

import (
	"fmt"
	"log"
	"os"

	"github.com/sigstore/sigstore/pkg/oauthflow"
	tuf "github.com/theupdateframework/go-tuf"
	"github.com/theupdateframework/go-tuf/pkg/keys"
	"github.com/theupdateframework/go-tuf/util"
)

func main() {
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	var p util.PassphraseFunc
	repo, err := tuf.NewRepo(tuf.FileSystemStore(dir, p))
	if err != nil {
		log.Fatal(err)
	}

	if err := repo.Init(false); err != nil {
		log.Fatal(err)
	}

	c := &keys.RealConnector{Flow: oauthflow.DefaultIDTokenGetter}
	key, err := keys.GenerateFulcioKey(c, "", "")
	if err != nil {
		log.Fatal(err)
	}

	ed25519Key, err := keys.GenerateEd25519Key()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("adding root")
	if err := repo.AddPrivateKey("root", ed25519Key); err != nil {
		log.Fatal(err)
	}
	fmt.Println("adding targets")

	if err := repo.AddPrivateKey("targets", ed25519Key); err != nil {
		log.Fatal(err)
	}
	fmt.Println("adding snapshot")

	if err := repo.AddPrivateKey("snapshot", ed25519Key); err != nil {
		log.Fatal(err)
	}
	fmt.Println("adding timestamp")

	if err := repo.AddPrivateKey("timestamp", key); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("staged/targets/README.md", []byte("foo"), 0644); err != nil {
		log.Fatal(err)
	}
	if err := repo.AddTargets([]string{"README.md"}, nil); err != nil {
		log.Fatal(err)
	}
	fmt.Println("committing")

	if err := repo.Snapshot(); err != nil {
		log.Fatal(err)
	}

	if err := repo.Timestamp(); err != nil {
		log.Fatal(err)
	}
	if err := repo.Commit(); err != nil {
		log.Fatal(err)
	}
}
