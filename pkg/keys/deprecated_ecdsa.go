package keys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/theupdateframework/go-tuf/data"
)

var (
	WarnDeprecatedEcdsaKey = "tuf: warning using deprecated ecdsa hex-encoded keys"
)

func NewDeprecatedEcdsaVerifier(opts ...VerifierOpts) Verifier {
	verifier := &ecdsaVerifierWithDeprecatedSupport{
		logger: log.New(io.Discard, "", log.LstdFlags),
	}
	for _, opt := range opts {
		if opt.Logger != nil {
			verifier.logger = opt.Logger
		}
	}
	return verifier
}

type ecdsaVerifierWithDeprecatedSupport struct {
	key *data.PublicKey
	// This will switch based on whether this is a PEM-encoded key
	// or a deprecated hex-encoded key.
	Verifier
	// This is used to write the deprecated warning to.
	logger *log.Logger
}

func (p *ecdsaVerifierWithDeprecatedSupport) UnmarshalPublicKey(key *data.PublicKey) error {
	p.key = key
	pemVerifier := &EcdsaVerifier{}
	if err := pemVerifier.UnmarshalPublicKey(key); err != nil {
		// Try the deprecated hex-encoded verifier
		hexVerifier := &deprecatedP256Verifier{
			logger: p.logger,
		}
		if err := hexVerifier.UnmarshalPublicKey(key); err != nil {
			return err
		}
		p.Verifier = hexVerifier
		return nil
	}
	p.Verifier = pemVerifier
	return nil
}

/*
   Deprecated ecdsaVerifier that used hex-encoded public keys.
   This MAY be used to verify existing metadata that used this
   old format. This will be deprecated soon, ensure that repositories
   are re-signed and clients receieve a fully compliant root.
*/

type deprecatedP256Verifier struct {
	PublicKey data.HexBytes `json:"public"`
	key       *data.PublicKey
	// This is used to write the deprecated warning to.
	logger *log.Logger
}

func (p *deprecatedP256Verifier) Public() string {
	return p.PublicKey.String()
}

func (p *deprecatedP256Verifier) Verify(msg, sigBytes []byte) error {
	x, y := elliptic.Unmarshal(elliptic.P256(), p.PublicKey)
	k := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	hash := sha256.Sum256(msg)

	if !ecdsa.VerifyASN1(k, hash[:], sigBytes) {
		return errors.New("tuf: deprecated ecdsa signature verification failed")
	}
	return nil
}

func (p *deprecatedP256Verifier) MarshalPublicKey() *data.PublicKey {
	return p.key
}

func (p *deprecatedP256Verifier) UnmarshalPublicKey(key *data.PublicKey) error {
	// Prepare decoder limited to 512Kb
	dec := json.NewDecoder(io.LimitReader(bytes.NewReader(key.Value), MaxJSONKeySize))

	// Unmarshal key value
	if err := dec.Decode(p); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("tuf: the public key is truncated or too large: %w", err)
		}
		return err
	}

	curve := elliptic.P256()

	// Parse as uncompressed marshalled point.
	x, _ := elliptic.Unmarshal(curve, p.PublicKey)
	if x == nil {
		return errors.New("tuf: invalid ecdsa public key point")
	}

	p.key = key
	p.logger.Print(WarnDeprecatedEcdsaKey)
	return nil
}
