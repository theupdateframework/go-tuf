// Copyright 2024 The Update Framework Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

type tufSigner interface {
	Sign(s signature.Signer) (*metadata.Signature, error)
}

/*
   Run this to sign test data, like this:
   ~/git/go-tuf/internal/testutils $ go run \
       signer/signer.go \
       -k repository_data/keystore/timestamp_key \
       -s rsassa-pss-sha256 \
       -f repository_data/repository/metadata/timestamp.json
*/

func main() {
	var scheme = flag.String("s", "", "set scheme to use for key")
	var key = flag.String("k", "", "key file to load")
	var f = flag.String("f", "", "file to sign")

	flag.Parse()

	if *scheme == "" {
		fmt.Println("no scheme is set")
		os.Exit(1)
	}
	if *key == "" {
		fmt.Println("no key provided")
		os.Exit(1)
	}
	if *f == "" {
		fmt.Println("no metadata file provided")
		os.Exit(1)
	}

	t, err := getTUFMDRole(*f)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	s, err := loadSigner(*key, *scheme)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var ts tufSigner

	switch t {
	case metadata.ROOT:
		var rmd metadata.Metadata[metadata.RootType]
		if _, err = rmd.FromFile(*f); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		rmd.Signatures = []metadata.Signature{}
		ts = &rmd
	case metadata.TARGETS:
		var tmd metadata.Metadata[metadata.TargetsType]
		if _, err = tmd.FromFile(*f); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		tmd.Signatures = []metadata.Signature{}
		ts = &tmd
	case metadata.SNAPSHOT:
		var smd metadata.Metadata[metadata.SnapshotType]
		if _, err = smd.FromFile(*f); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		smd.Signatures = []metadata.Signature{}
		ts = &smd
	case metadata.TIMESTAMP:
		var tsmd metadata.Metadata[metadata.TimestampType]
		if _, err = tsmd.FromFile(*f); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		tsmd.Signatures = []metadata.Signature{}
		ts = &tsmd
	}

	if _, err = ts.Sign(s); err != nil {
		fmt.Printf("failed to sign metadata of type %s: %s\n",
			t, err)
		os.Exit(1)
	}

	if err = persist(*f, ts); err != nil {
		fmt.Printf("failed to persist updated metadata %s: %s\n",
			*f, err)
	}
}

func persist(p string, md any) error {
	jsonBytes, err := json.MarshalIndent(md, "", " ")
	if err != nil {
		return err
	}

	err = os.WriteFile(p, jsonBytes, 0600)
	return err
}

func loadSigner(k, s string) (signature.Signer, error) {
	var pk any
	var err error
	var opts []signature.LoadOption
	var rawKey []byte

	switch s {
	case metadata.KeySchemeRSASSA_PSS_SHA256:
		if rawKey, err = getPemBytes(k); err != nil {
			return nil, err
		}
		if pk, err = x509.ParsePKCS1PrivateKey(rawKey); err != nil {
			return nil, err
		}
		var pssOpt = rsa.PSSOptions{Hash: crypto.SHA256}
		opts = append(opts, options.WithRSAPSS(&pssOpt))
	default:
		return nil, fmt.Errorf("unsupported key scheme %s", s)
	}

	return signature.LoadSignerWithOpts(pk, opts...)
}

func getPemBytes(p string) ([]byte, error) {
	var b []byte
	var block *pem.Block
	var err error

	if b, err = os.ReadFile(p); err != nil {
		return nil, err
	}

	if block, _ = pem.Decode(b); len(block.Bytes) == 0 {
		return nil, errors.New("empty PEM block")
	}

	return block.Bytes, nil
}

func getTUFMDRole(p string) (string, error) {
	var m map[string]any

	mdBytes, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", p, err)
	}

	if err := json.Unmarshal(mdBytes, &m); err != nil {
		return "", fmt.Errorf("failed to parse TUF metadata: %w", err)
	}
	signedType := m["signed"].(map[string]any)["_type"].(string)
	switch signedType {
	case metadata.ROOT:
		fallthrough
	case metadata.TARGETS:
		fallthrough
	case metadata.SNAPSHOT:
		fallthrough
	case metadata.TIMESTAMP:
		return signedType, nil
	default:
		return "", fmt.Errorf("unsupported role '%s'", signedType)
	}
}
