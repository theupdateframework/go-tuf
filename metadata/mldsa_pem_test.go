// Copyright 2026 The Update Framework Authors
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"crypto/mldsa"
	"encoding/pem"
	"testing"
)

func TestMLDSAPEMEnvelope(t *testing.T) {
	private, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	public, err := KeyFromPublicKey(private.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(public.Value.PublicKey))
	for _, tc := range []struct {
		name, value string
		valid       bool
	}{
		{"original", public.Value.PublicKey, true},
		{"trailing whitespace", public.Value.PublicKey + "\n\t", true},
		{"second key", public.Value.PublicKey + public.Value.PublicKey, false},
		{"trailing data", public.Value.PublicKey + "unexpected", false},
		{"wrong block type", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})), false},
		{"headers", string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: map[string]string{"Comment": "unexpected"}, Bytes: block.Bytes})), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := *public
			candidate.Value.PublicKey = tc.value
			_, err := candidate.ToPublicKey()
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}
