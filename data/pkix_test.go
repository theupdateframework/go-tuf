package data

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"

	. "gopkg.in/check.v1"
)

const ecdsaKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEftgasQA68yvumeXZmcOTSIHKfbmx
WT1oYuRF0Un3tKxnzip6xAYwlz0Dt96DUh+0P7BruHH2O6s4MiRR9/TuNw==
-----END PUBLIC KEY-----
`

type PKIXSuite struct{}

var _ = Suite(&PKIXSuite{})

func (PKIXSuite) TestMarshalJSON(c *C) {
	block, _ := pem.Decode([]byte(ecdsaKey))
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	c.Assert(err, IsNil)
	k := PKIXPublicKey{PublicKey: key}
	buf, err := json.Marshal(&k)
	c.Assert(err, IsNil)
	var val string
	err = json.Unmarshal(buf, &val)
	c.Assert(err, IsNil)
	c.Assert(val, Equals, ecdsaKey)
}

func (PKIXSuite) TestUnmarshalJSON(c *C) {
	buf, err := json.Marshal(ecdsaKey)
	c.Assert(err, IsNil)
	var k PKIXPublicKey
	err = json.Unmarshal(buf, &k)
	c.Assert(err, IsNil)
	c.Assert(k.PublicKey, FitsTypeOf, (*ecdsa.PublicKey)(nil))
}
