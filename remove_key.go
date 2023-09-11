package main

import (
	"os"
	"path/filepath"

	"github.com/theupdateframework/go-tuf"
	"github.com/flynn/go-docopt"
)


type EncryptedKey struct{
	EncryptedData string `json:"encrypted_data"`
}

func init() {
	register("remove-key", cmdRemoveKey, `
usage: tuf remove-key [--expires=<days>] <role> <id>

Remove a signing key

Before the key is removed the key will be first revoked
The key will then be removed from the root metadata file and if the key is present in 
"keys" directory it will also be removed

Options:

  --expires=<days>   Set the root metadata file to expire <days> days from now.
`)
}

//
func cmdRemoveKey(args *docopt.Args, repo *tuf.Repo) error {
	role := args.String["<roles>"]
	keyID := args.String["<id>"]

	//Revoke the Key 
	if err := repo.RevokeKey(role, keyID); err != nil {
		return err
	}

	//Read the encryted key data from the file 
	encryptedKeyPath := filepath.Join("keys", keyID+".json")
	encryptedData, err := ReadFile(encryptedKeyPath)
	if err != nil {
		return err 
	}

	//Parse the encrypted JSON data 
	var encryptedKey EncryptedKey
	err = json.Unmarshal(encryptedData, & encryptedKey)
	if err != nil{
		return err 
	}

	//Decrypt the key data ******(i.e. implement the decryption logic)
	decryptKeyData, err := decryptKeyData(encryptedKey, EncryptedData)
	if err != nil{
		return err 
	}
	
	//We now have the decrypted key data, proceed with the removal 
	keyPath := filepath.Join("keys", keyID)
	if _, err := os.Stat(keyPath); err == nil {
		if err := os.Remove(keyPath); err != nil {
			return err
		}
	}
	return nil
	
}


func decryptKeyData(encryptedData string) (string, error){
	//Implement your decryption logic here 
	//This is where you would decrypt the encrypted key data 
	//and return the decrypted key data 
	return "", nil 

}