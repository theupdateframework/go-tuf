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

// Package helpers provides composable test utilities for go-tuf tests.
//
// Design principles:
//   - All helpers accept *testing.T or *testing.B and call t.Helper() first.
//   - Use t.TempDir() instead of custom directory managers; the testing package
//     cleans up automatically.
//   - No third-party assertion libraries: helpers signal failures via t.Errorf
//     and t.Fatalf, matching the standard library style.
//   - JSON fixture builders do not depend on *testing.T so they can be used
//     in fuzz seed functions without the &testing.T{} anti-pattern.
package helpers

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// WriteTestFile writes content to a file in the given directory and returns the
// full path. The test fails immediately if the write fails.
func WriteTestFile(t *testing.T, dir, filename string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("WriteTestFile(%q): %v", path, err)
	}
	return path
}

// ReadTestFile reads and returns the content of a file. The test fails
// immediately if the read fails.
func ReadTestFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadTestFile(%q): %v", path, err)
	}
	return data
}

// StripWhitespace removes all ASCII whitespace characters from b.
func StripWhitespace(data []byte) []byte {
	result := make([]byte, 0, len(data))
	for _, b := range data {
		if b != ' ' && b != '\t' && b != '\n' && b != '\r' {
			result = append(result, b)
		}
	}
	return result
}

// CompareJSON asserts that got and want represent the same JSON value,
// normalising away whitespace differences. The test is marked failed (but
// not stopped) when they differ.
func CompareJSON(t *testing.T, got, want []byte) {
	t.Helper()

	var gotVal, wantVal any
	if err := json.Unmarshal(got, &gotVal); err != nil {
		t.Fatalf("CompareJSON: unmarshal got: %v", err)
	}
	if err := json.Unmarshal(want, &wantVal); err != nil {
		t.Fatalf("CompareJSON: unmarshal want: %v", err)
	}

	gotNorm, err := json.Marshal(gotVal)
	if err != nil {
		t.Fatalf("CompareJSON: re-marshal got: %v", err)
	}
	wantNorm, err := json.Marshal(wantVal)
	if err != nil {
		t.Fatalf("CompareJSON: re-marshal want: %v", err)
	}

	if !bytes.Equal(gotNorm, wantNorm) {
		t.Errorf("JSON mismatch:\ngot:  %s\nwant: %s", gotNorm, wantNorm)
	}
}

// GenerateTestKeyPair generates a fresh Ed25519 key pair. The test fails
// immediately if key generation fails.
func GenerateTestKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateTestKeyPair: %v", err)
	}
	return pub, priv
}

// AssertErrorContains fails the test if err is nil or if its message does not
// contain expectedMsg.
func AssertErrorContains(t *testing.T, err error, expectedMsg string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", expectedMsg)
	}
	if !strings.Contains(err.Error(), expectedMsg) {
		t.Fatalf("expected error containing %q, got %q", expectedMsg, err.Error())
	}
}

// AssertNoError fails the test immediately if err is non-nil.
func AssertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// MustMarshal marshals v to JSON. The test fails immediately if marshalling
// fails.
func MustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("MustMarshal: %v", err)
	}
	return data
}

// MustUnmarshal unmarshals data into a value of type T. The test fails
// immediately if unmarshalling fails.
func MustUnmarshal[T any](t *testing.T, data []byte) T {
	t.Helper()
	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("MustUnmarshal: %v", err)
	}
	return result
}

// CreateInvalidJSON returns a map of named byte slices that represent various
// kinds of invalid or malformed TUF metadata. Useful for error-path tests.
func CreateInvalidJSON() map[string][]byte {
	return map[string][]byte{
		"empty":            []byte(""),
		"invalid_json":     []byte("{invalid json}"),
		"missing_signed":   []byte(`{"signatures": []}`),
		"wrong_type":       []byte(`{"signed": {"_type": "wrong"}, "signatures": []}`),
		"missing_version":  []byte(`{"signed": {"_type": "root"}, "signatures": []}`),
		"negative_version": []byte(`{"signed": {"_type": "root", "version": -1}, "signatures": []}`),
	}
}

// HexBytes is a convenience type alias for testing scenarios that require
// hex-encoded byte slices without importing the full metadata package.
type HexBytes []byte

func (h HexBytes) String() string {
	return fmt.Sprintf("%x", []byte(h))
}

// — JSON fixture builders —
//
// These functions do not accept *testing.T so they can be called from fuzz
// seed setup (f.Add) without the &testing.T{} anti-pattern.

// BuildRootJSON returns a minimal, valid root.json body as JSON bytes.
func BuildRootJSON() []byte {
	expiry := time.Now().UTC().Add(24 * time.Hour)
	root := map[string]any{
		"signed": map[string]any{
			"_type":               "root",
			"spec_version":        "1.0.31",
			"version":             1,
			"expires":             expiry.Format(time.RFC3339),
			"consistent_snapshot": true,
			"keys":                map[string]any{},
			"roles": map[string]any{
				"root":      map[string]any{"keyids": []string{}, "threshold": 1},
				"targets":   map[string]any{"keyids": []string{}, "threshold": 1},
				"snapshot":  map[string]any{"keyids": []string{}, "threshold": 1},
				"timestamp": map[string]any{"keyids": []string{}, "threshold": 1},
			},
		},
		"signatures": []any{},
	}
	data, err := json.Marshal(root)
	if err != nil {
		panic(fmt.Sprintf("BuildRootJSON: %v", err))
	}
	return data
}

// BuildTargetsJSON returns a minimal, valid targets.json body as JSON bytes.
func BuildTargetsJSON() []byte {
	expiry := time.Now().UTC().Add(24 * time.Hour)
	targets := map[string]any{
		"signed": map[string]any{
			"_type":        "targets",
			"spec_version": "1.0.31",
			"version":      1,
			"expires":      expiry.Format(time.RFC3339),
			"targets":      map[string]any{},
		},
		"signatures": []any{},
	}
	data, err := json.Marshal(targets)
	if err != nil {
		panic(fmt.Sprintf("BuildTargetsJSON: %v", err))
	}
	return data
}

// BuildSnapshotJSON returns a minimal, valid snapshot.json body as JSON bytes.
func BuildSnapshotJSON() []byte {
	expiry := time.Now().UTC().Add(24 * time.Hour)
	snapshot := map[string]any{
		"signed": map[string]any{
			"_type":        "snapshot",
			"spec_version": "1.0.31",
			"version":      1,
			"expires":      expiry.Format(time.RFC3339),
			"meta": map[string]any{
				"targets.json": map[string]any{"version": 1},
			},
		},
		"signatures": []any{},
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		panic(fmt.Sprintf("BuildSnapshotJSON: %v", err))
	}
	return data
}

// BuildTimestampJSON returns a minimal, valid timestamp.json body as JSON bytes.
func BuildTimestampJSON() []byte {
	expiry := time.Now().UTC().Add(24 * time.Hour)
	timestamp := map[string]any{
		"signed": map[string]any{
			"_type":        "timestamp",
			"spec_version": "1.0.31",
			"version":      1,
			"expires":      expiry.Format(time.RFC3339),
			"meta": map[string]any{
				"snapshot.json": map[string]any{"version": 1},
			},
		},
		"signatures": []any{},
	}
	data, err := json.Marshal(timestamp)
	if err != nil {
		panic(fmt.Sprintf("BuildTimestampJSON: %v", err))
	}
	return data
}

// — Test-context variants (t.Helper wrappers for backwards compatibility) —

// CreateTestRootJSON returns BuildRootJSON() and registers a test helper.
// Prefer calling BuildRootJSON() directly when not inside a test function.
func CreateTestRootJSON(t *testing.T) []byte {
	t.Helper()
	return BuildRootJSON()
}

// CreateTestTargetsJSON returns BuildTargetsJSON() and registers a test helper.
func CreateTestTargetsJSON(t *testing.T) []byte {
	t.Helper()
	return BuildTargetsJSON()
}

// CreateTestSnapshotJSON returns BuildSnapshotJSON() and registers a test helper.
func CreateTestSnapshotJSON(t *testing.T) []byte {
	t.Helper()
	return BuildSnapshotJSON()
}

// CreateTestTimestampJSON returns BuildTimestampJSON() and registers a test helper.
func CreateTestTimestampJSON(t *testing.T) []byte {
	t.Helper()
	return BuildTimestampJSON()
}
