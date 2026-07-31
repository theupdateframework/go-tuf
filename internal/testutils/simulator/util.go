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

package simulator

import (
	"crypto"
	"crypto/ed25519"
	"log/slog"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sigstore/sigstore/pkg/signature"
)

// createKey generates a new ed25519 public-private key pair and a signer using the private key.
// It returns pointers to the public key, private key, and the signer.
// If there is an error during the key generation or signer loading, it logs the error and continues.
func createKey() (*ed25519.PublicKey, *ed25519.PrivateKey, *signature.Signer) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		slog.Error("Failed to generate key", "err", err)
	}

	signer, err := signature.LoadSigner(private, crypto.Hash(0))
	if err != nil {
		slog.Error("Failed to load signer", "err", err)
	}

	return &public, &private, &signer
}

// trimPrefix is a function that takes a path and a prefix as input.
// It checks if the path starts with a drive letter (e.g., "C:\").
// If it does, it trims the prefix from the path.
// If it doesn't, it parses the path as a URL and trims the prefix from the URL's path.
// The function returns the trimmed path or an error if the path cannot be parsed as a URL.
func trimPrefix(path string, prefix string) (string, error) {
	var toTrim string
	if match, _ := regexp.MatchString(`^[a-zA-Z]:\\`, path); match {
		toTrim = path
	} else {
		parsedURL, err := url.Parse(path)
		if err != nil {
			return "", err
		}

		toTrim = parsedURL.Path
	}

	return strings.TrimPrefix(toTrim, prefix), nil
}

func hasPrefix(path, prefix string) bool {
	return strings.HasPrefix(filepath.ToSlash(path), prefix)
}

func hasSuffix(path, prefix string) bool {
	return strings.HasSuffix(filepath.ToSlash(path), prefix)
}
