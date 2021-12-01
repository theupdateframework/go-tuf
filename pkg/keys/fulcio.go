package keys

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"

	"github.com/coreos/go-oidc"
	httptransport "github.com/go-openapi/runtime/client"
	fulcioClient "github.com/sigstore/fulcio/pkg/client"

	"github.com/go-openapi/strfmt"
	"github.com/sigstore/fulcio/pkg/generated/client/operations"
	"github.com/sigstore/fulcio/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/theupdateframework/go-tuf/data"
)

func init() {
	SignerMap.Store(data.KeyTypeSigstore_Fulcio_SHA256, NewFulcioSigner)
	VerifierMap.Store(data.KeyTypeSigstore_Fulcio_SHA256, NewFulcioVerifier)
}

func NewFulcioSigner() Signer {
	return &fulcioSigner{}
}

func NewFulcioVerifier() Verifier {
	return &fulcioVerifier{}
}

type fulcioVerifier struct {
	Identity string `json:"identity"`
	Issuer   string `json:"issuer"`
	key      *data.PublicKey
}

func (e *fulcioVerifier) Public() string {
	return fmt.Sprintf("%s:%s", e.Issuer, e.Identity)
}

func (e *fulcioVerifier) Verify(msg []byte, signature data.Signature) error {
	// Check signature verification by extracting public key out of x509 cert
	certs, err := cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(signature.Certificate))
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		return errors.New("tuf: no certs found in pem certificates")
	}

	cert := certs[0]
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("tuf: invalid public key type in certificate")
	}

	var sig ecdsaSignature
	if _, err := asn1.Unmarshal(signature.Signature, &sig); err != nil {
		return err
	}

	hash := sha256.Sum256(msg)
	if !ecdsa.Verify(pubKey, hash[:], sig.R, sig.S) {
		return errors.New("tuf: ecdsa signature verification failed")
	}

	// Check certificate identity and issuer matches the key value.
	if cert.EmailAddresses == nil || cert.EmailAddresses[0] != e.Identity {
		return errors.New("tuf: unexpected certificate identity")
	}

	if certIssuerExtension(cert) != e.Issuer {
		return errors.New("tuf: unexpected certificate issuer")
	}

	// TODO: Check certificate chain. Verify certificate against Fulcio Root CA

	// TODO: Check the rekor log.
	return nil
}

func (e *fulcioVerifier) MarshalPublicKey() *data.PublicKey {
	return e.key
}

func (e *fulcioVerifier) UnmarshalPublicKey(key *data.PublicKey) error {
	e.key = key
	if err := json.Unmarshal(key.Value, e); err != nil {
		return err
	}
	if e.Identity == "" {
		return errors.New("tuf: missing identity for Fulcio verification key")
	}
	if e.Issuer == "" {
		return errors.New("tuf: missing issuer for Fulcio verification key")
	}
	return nil
}

type fulcioPrivateKeyValue struct {
	// This is the same structure as the verifier since all private key material is ephemeral.
	Identity string `json:"identity"`
	Issuer   string `json:"issuer"`
}

type fulcioSigner struct {
	fulcioPrivateKeyValue

	keyType       string
	keyScheme     string
	keyAlgorithms []string
}

// For testing.
type OidcConnector interface {
	OIDConnect(string, string, string) (*oauthflow.OIDCIDToken, error)
}

type RealConnector struct {
	Flow oauthflow.TokenGetter
}

func (rf *RealConnector) OIDConnect(url, clientID, secret string) (*oauthflow.OIDCIDToken, error) {
	return oauthflow.OIDConnect(url, clientID, secret, rf.Flow)
}

type claims struct {
	FederatedClaims federatedclaims `json:"federated_claims"`
}

type federatedclaims struct {
	ConnectorID string `json:"connector_id"`
}

func GenerateFulcioKey(connector OidcConnector, issuer string, identity string) (*fulcioSigner, error) {
	// During signing, we use OIDC flow to gather the identity and issuer automatically.
	// No keys need to be created here.
	if issuer == "" || identity == "" {
		// Use OIDC flow to automatically deduce (self) identity here.
		tok, err := connector.OIDConnect(data.KeyOidcIssuerSigstore_Fulcio, "sigstore", "")
		if err != nil {
			return nil, err
		}
		identity = tok.Subject

		issuer, err = issuerFromToken(tok)
		if err != nil {
			return nil, err
		}
	}
	return &fulcioSigner{
		fulcioPrivateKeyValue: fulcioPrivateKeyValue{Identity: identity, Issuer: issuer},
		keyType:               data.KeyTypeSigstore_Fulcio_SHA256,
		keyScheme:             data.KeySchemeSigstore_Fulcio_SHA256,
		keyAlgorithms:         data.HashAlgorithms,
	}, nil
}

func issuerFromToken(tok *oauthflow.OIDCIDToken) (string, error) {
	// Parse raw subject to get issuer
	provider, err := oidc.NewProvider(context.Background(), data.KeyOidcIssuerSigstore_Fulcio)
	if err != nil {
		return "", err
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: "sigstore"})
	parsedIDToken, err := verifier.Verify(context.Background(), tok.RawString)
	if err != nil {
		return "", err
	}

	claims := claims{}
	if err := parsedIDToken.Claims(&claims); err != nil {
		return "", err
	}
	return claims.FederatedClaims.ConnectorID, nil
}

func certIssuerExtension(cert *x509.Certificate) string {
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "1.3.6.1.4.1.57264.1.1" {
			return string(ext.Value)
		}
	}
	return ""
}

func (e *fulcioSigner) SignMessage(message []byte) ([]data.Signature, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(message)
	sig, err := priv.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}

	// Get Fulcio-issued certificate
	c := &RealConnector{}
	c.Flow = oauthflow.DefaultIDTokenGetter
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	tok, err := c.OIDConnect(data.KeyOidcIssuerSigstore_Fulcio, "sigstore", "")
	if err != nil {
		return nil, err
	}

	// Check that this matches with the signer
	if e.Identity != tok.Subject {
		return nil, fmt.Errorf("tuf: unexpected signer identity, expected %s, got %s", e.Identity, tok.Subject)
	}

	// Check that the issuer matches
	issuer, err := issuerFromToken(tok)
	if err != nil {
		return nil, err
	}
	if e.Issuer != issuer {
		return nil, fmt.Errorf("tuf: unexpected signer identity, expected %s, got %s", e.Issuer, issuer)
	}

	// Sign the email address as part of the request
	h := sha256.Sum256([]byte(tok.Subject))
	proof, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		return nil, err
	}

	bearerAuth := httptransport.BearerToken(tok.RawString)

	content := strfmt.Base64(pubBytes)
	signedChallenge := strfmt.Base64(proof)
	params := operations.NewSigningCertParams()
	params.SetCertificateRequest(
		&models.CertificateRequest{
			PublicKey: &models.CertificateRequestPublicKey{
				Algorithm: models.CertificateRequestPublicKeyAlgorithmEcdsa,
				Content:   &content,
			},
			SignedEmailAddress: &signedChallenge,
		},
	)

	fulcioServer, err := url.Parse(fulcioClient.SigstorePublicServerURL)
	if err != nil {
		return nil, err
	}
	fClient := fulcioClient.New(fulcioServer)

	resp, err := fClient.Operations.SigningCert(params, bearerAuth)
	if err != nil {
		return nil, err
	}

	// Split the cert and the chain
	certBlock, _ := pem.Decode([]byte(resp.Payload))
	certPem := pem.EncodeToMemory(certBlock)

	ids := e.PublicData().IDs()
	sigs := make([]data.Signature, 0, len(ids))
	for _, id := range ids {
		sigs = append(sigs, data.Signature{
			KeyID:       id,
			Signature:   sig,
			Certificate: certPem,
		})
	}

	// TODO: Upload (msg, sig, cert) to Rekor for timestamp validation.
	return sigs, nil
}

func (e *fulcioSigner) MarshalPrivateKey() (*data.PrivateKey, error) {
	valueBytes, err := json.Marshal(e.fulcioPrivateKeyValue)
	if err != nil {
		return nil, err
	}
	return &data.PrivateKey{
		Type:       e.keyType,
		Scheme:     e.keyScheme,
		Algorithms: e.keyAlgorithms,
		Value:      valueBytes,
	}, nil
}

func (e *fulcioSigner) UnmarshalPrivateKey(key *data.PrivateKey) error {
	keyValue := &fulcioPrivateKeyValue{}
	if err := json.Unmarshal(key.Value, keyValue); err != nil {
		return err
	}
	*e = fulcioSigner{
		fulcioPrivateKeyValue: *keyValue,
		keyType:               key.Type,
		keyScheme:             key.Scheme,
		keyAlgorithms:         key.Algorithms,
	}
	return nil
}

func (e *fulcioSigner) PublicData() *data.PublicKey {
	// Do we ever need public data before signing?
	keyValBytes, _ := json.Marshal(fulcioVerifier{
		Identity: e.fulcioPrivateKeyValue.Identity,
		Issuer:   e.fulcioPrivateKeyValue.Issuer})
	return &data.PublicKey{
		Type:       e.keyType,
		Scheme:     e.keyScheme,
		Algorithms: e.keyAlgorithms,
		Value:      keyValBytes,
	}
}
