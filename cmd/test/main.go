package main

import (
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

	if err := repo.AddPrivateKey("root", key); err != nil {
		log.Fatal(err)
	}

	if err := repo.AddPrivateKey("targets", key); err != nil {
		log.Fatal(err)
	}

	if err := repo.AddPrivateKey("snapshot", key); err != nil {
		log.Fatal(err)
	}

	if err := repo.AddPrivateKey("timestamp", key); err != nil {
		log.Fatal(err)
	}

}
