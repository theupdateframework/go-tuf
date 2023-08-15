package set_ecdsa

import (
	"errors"

	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/pkg/keys"
)

/*
	Importing this package will allow support for both hex-encoded ECDSA
	verifiers and PEM-encoded ECDSA verifiers.
	Note that this package imports "github.com/theupdateframework/go-tuf/pkg/keys"
	and overrides the ECDSA verifier loaded at init time in that package.
*/

func init() {
	_, ok := keys.VerifierMap.Load(data.KeyTypeECDSA_SHA2_P256)
	if !ok {
		panic(errors.New("expected to override previously loaded PEM-only ECDSA verifier"))
	}
	// store a mapping for both data.KeyTypeECDSA_SHA2_P256_OLD_FMT and data.KeyTypeECDSA_SHA2_P256
	// in case a client is verifying using both the old non-compliant format and a newly generated root
	keys.VerifierMap.Store(data.KeyTypeECDSA_SHA2_P256, keys.NewDeprecatedEcdsaVerifier)         // compliant format
	keys.VerifierMap.Store(data.KeyTypeECDSA_SHA2_P256_OLD_FMT, keys.NewDeprecatedEcdsaVerifier) // deprecated format
}
