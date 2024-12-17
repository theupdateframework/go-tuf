package rsapss

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

func LoadRSAPSSSignerFromPEMFile(p string) (signature.Signer, error) {
	var b []byte
	var block *pem.Block
	var pk any
	var err error

	if b, err = os.ReadFile(p); err != nil {
		return nil, err
	}

	if block, _ = pem.Decode(b); len(block.Bytes) == 0 {
		return nil, errors.New("empty PEM block")
	}

	if pk, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		return nil, err
	}
	var pssOpt = rsa.PSSOptions{Hash: crypto.SHA256}

	return signature.LoadSignerWithOpts(pk, options.WithRSAPSS(&pssOpt))
}
