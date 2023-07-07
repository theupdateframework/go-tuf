package encrypted

import (
	"encoding/json"
	"strings"
	"testing"

	. "gopkg.in/check.v1"
)

var (
	kdfVectors = map[KDFParameterStrength][]byte{
		Legacy:   []byte(`{"kdf":{"name":"scrypt","params":{"N":32768,"r":8,"p":1},"salt":"WO3mVvyTwJ9vwT5/Tk5OW5WPIBUofMjcpEfrLnfY4uA="},"cipher":{"name":"nacl/secretbox","nonce":"tCy7HcTFr4uxv4Nrg/DWmncuZ148U1MX"},"ciphertext":"08n43p5G5yviPEZpO7tPPF4aZQkWiWjkv4taFdhDBA0tamKH4nw="}`),
		Standard: []byte(`{"kdf":{"name":"scrypt","params":{"N":65536,"r":8,"p":1},"salt":"FhzPOt9/bJG4PTq6lQ6ecG6GzaOuOy/ynG5+yRiFlNs="},"cipher":{"name":"nacl/secretbox","nonce":"aw1ng1jHaDz/tQ7V2gR9O2+IGQ8xJEuE"},"ciphertext":"HycvuLZL4sYH0BrYTh4E/H20VtAW6u5zL5Pr+IBjYLYnCPzDkq8="}`),
		OWASP:    []byte(`{"kdf":{"name":"scrypt","params":{"N":131072,"r":8,"p":1},"salt":"m38E3kouJTtiheLQN22NQ8DTito5hrjpUIskqcd375k="},"cipher":{"name":"nacl/secretbox","nonce":"Y6PM13yA+o44pE/W1ZBwczeGnTV/m9Zc"},"ciphertext":"6H8sqj1K6B6yDjtH5AQ6lbFigg/C2yDDJc4rYJ79w9aVPImFIPI="}`),
	}
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type EncryptedSuite struct{}

var _ = Suite(&EncryptedSuite{})

var plaintext = []byte("reallyimportant")

func (EncryptedSuite) TestRoundtrip(c *C) {
	passphrase := []byte("supersecret")

	enc, err := Encrypt(plaintext, passphrase)
	c.Assert(err, IsNil)

	// successful decrypt
	dec, err := Decrypt(enc, passphrase)
	c.Assert(err, IsNil)
	c.Assert(dec, DeepEquals, plaintext)

	// wrong passphrase
	passphrase[0] = 0
	dec, err = Decrypt(enc, passphrase)
	c.Assert(err, NotNil)
	c.Assert(dec, IsNil)
}

func (EncryptedSuite) TestTamperedRoundtrip(c *C) {
	passphrase := []byte("supersecret")

	enc, err := Encrypt(plaintext, passphrase)
	c.Assert(err, IsNil)

	data := &data{}
	err = json.Unmarshal(enc, data)
	c.Assert(err, IsNil)

	data.Ciphertext[0] = ^data.Ciphertext[0]

	enc, _ = json.Marshal(data)

	dec, err := Decrypt(enc, passphrase)
	c.Assert(err, NotNil)
	c.Assert(dec, IsNil)
}

func (EncryptedSuite) TestDecrypt(c *C) {
	enc := []byte(`{"kdf":{"name":"scrypt","params":{"N":32768,"r":8,"p":1},"salt":"N9a7x5JFGbrtB2uBR81jPwp0eiLR4A7FV3mjVAQrg1g="},"cipher":{"name":"nacl/secretbox","nonce":"2h8HxMmgRfuYdpswZBQaU3xJ1nkA/5Ik"},"ciphertext":"SEW6sUh0jf2wfdjJGPNS9+bkk2uB+Cxamf32zR8XkQ=="}`)
	passphrase := []byte("supersecret")

	dec, err := Decrypt(enc, passphrase)
	c.Assert(err, IsNil)
	c.Assert(dec, DeepEquals, plaintext)
}

func (EncryptedSuite) TestMarshalUnmarshal(c *C) {
	passphrase := []byte("supersecret")

	wrapped, err := Marshal(plaintext, passphrase)
	c.Assert(err, IsNil)
	c.Assert(wrapped, NotNil)

	var protected []byte
	err = Unmarshal(wrapped, &protected, passphrase)
	c.Assert(err, IsNil)
	c.Assert(protected, DeepEquals, plaintext)
}

func (EncryptedSuite) TestInvalidKDFSettings(c *C) {
	passphrase := []byte("supersecret")

	wrapped, err := MarshalWithCustomKDFParameters(plaintext, passphrase, 0)
	c.Assert(err, IsNil)
	c.Assert(wrapped, NotNil)

	var protected []byte
	err = Unmarshal(wrapped, &protected, passphrase)
	c.Assert(err, IsNil)
	c.Assert(protected, DeepEquals, plaintext)
}

func (EncryptedSuite) TestLegacyKDFSettings(c *C) {
	passphrase := []byte("supersecret")

	wrapped, err := MarshalWithCustomKDFParameters(plaintext, passphrase, Legacy)
	c.Assert(err, IsNil)
	c.Assert(wrapped, NotNil)

	var protected []byte
	err = Unmarshal(wrapped, &protected, passphrase)
	c.Assert(err, IsNil)
	c.Assert(protected, DeepEquals, plaintext)
}

func (EncryptedSuite) TestStandardKDFSettings(c *C) {
	passphrase := []byte("supersecret")

	wrapped, err := MarshalWithCustomKDFParameters(plaintext, passphrase, Standard)
	c.Assert(err, IsNil)
	c.Assert(wrapped, NotNil)

	var protected []byte
	err = Unmarshal(wrapped, &protected, passphrase)
	c.Assert(err, IsNil)
	c.Assert(protected, DeepEquals, plaintext)
}

func (EncryptedSuite) TestOWASPKDFSettings(c *C) {
	passphrase := []byte("supersecret")

	wrapped, err := MarshalWithCustomKDFParameters(plaintext, passphrase, OWASP)
	c.Assert(err, IsNil)
	c.Assert(wrapped, NotNil)

	var protected []byte
	err = Unmarshal(wrapped, &protected, passphrase)
	c.Assert(err, IsNil)
	c.Assert(protected, DeepEquals, plaintext)
}

func (EncryptedSuite) TestKDFSettingVectors(c *C) {
	passphrase := []byte("supersecret")

	for _, v := range kdfVectors {
		var protected []byte
		err := Unmarshal(v, &protected, passphrase)
		c.Assert(err, IsNil)
		c.Assert(protected, DeepEquals, plaintext)
	}
}

func (EncryptedSuite) TestUnsupportedKDFParameters(c *C) {
	enc := []byte(`{"kdf":{"name":"scrypt","params":{"N":99,"r":99,"p":99},"salt":"cZFcQJdwPhPyhU1R4qkl0qVOIjZd4V/7LYYAavq166k="},"cipher":{"name":"nacl/secretbox","nonce":"7vhRS7j0hEPBWV05skAdgLj81AkGeE7U"},"ciphertext":"6WYU/YSXVbYzl/NzaeAzmjLyfFhOOjLc0d8/GFV0aBFdJvyCcXc="}`)
	passphrase := []byte("supersecret")

	dec, err := Decrypt(enc, passphrase)
	c.Assert(err, NotNil)
	c.Assert(dec, IsNil)
	c.Assert(strings.Contains(err.Error(), "unsupported scrypt parameters"), Equals, true)
}
