package data

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
)

type PKIXPublicKey struct {
	crypto.PublicKey
}

func (p *PKIXPublicKey) MarshalJSON() ([]byte, error) {
	bytes, err := x509.MarshalPKIXPublicKey(p.PublicKey)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: bytes,
	})
	return json.Marshal(string(pemBytes))
}

func (p *PKIXPublicKey) UnmarshalJSON(b []byte) error {
	var pemValue string
	if err := json.Unmarshal(b, &pemValue); err != nil {
		return err
	}
	block, _ := pem.Decode([]byte(pemValue))
	if block == nil {
		return errors.New("invalid PEM value")
	}
	if block.Type != "PUBLIC KEY" {
		return fmt.Errorf("invalid block type: %s", block.Type)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	p.PublicKey = pub
	return nil
}
