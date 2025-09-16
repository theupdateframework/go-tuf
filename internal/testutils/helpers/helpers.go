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

package helpers

import (
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

// TestCase represents a generic test case structure for table-driven tests
type TestCase[T any] struct {
	Name     string
	Setup    func(t *testing.T) T
	Input    T
	Want     T
	WantErr  bool
	ErrorMsg string
	Cleanup  func(t *testing.T)
}

// TempDirManager manages temporary directories for tests
type TempDirManager struct {
	baseTempDir string
	tempDirs    []string
}

// NewTempDirManager creates a new temporary directory manager
func NewTempDirManager() *TempDirManager {
	return &TempDirManager{
		baseTempDir: os.TempDir(),
		tempDirs:    make([]string, 0),
	}
}

// CreateTempDir creates a temporary directory and tracks it for cleanup
func (tdm *TempDirManager) CreateTempDir(t *testing.T, pattern string) string {
	t.Helper()
	tempDir, err := os.MkdirTemp(tdm.baseTempDir, pattern)
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	tdm.tempDirs = append(tdm.tempDirs, tempDir)
	return tempDir
}

// Cleanup removes all tracked temporary directories
func (tdm *TempDirManager) Cleanup(t *testing.T) {
	t.Helper()
	for _, dir := range tdm.tempDirs {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("failed to remove temp dir %s: %v", dir, err)
		}
	}
	tdm.tempDirs = tdm.tempDirs[:0]
}

// WriteTestFile writes content to a file in the given directory
func WriteTestFile(t *testing.T, dir, filename string, content []byte) string {
	t.Helper()
	filePath := filepath.Join(dir, filename)
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		t.Fatalf("failed to write test file %s: %v", filePath, err)
	}
	return filePath
}

// ReadTestFile reads content from a file
func ReadTestFile(t *testing.T, filePath string) []byte {
	t.Helper()
	content, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read test file %s: %v", filePath, err)
	}
	return content
}

// StripWhitespaces removes all whitespace characters from a byte slice
func StripWhitespaces(data []byte) []byte {
	result := make([]byte, 0, len(data))
	for _, b := range data {
		if b != ' ' && b != '\t' && b != '\n' && b != '\r' {
			result = append(result, b)
		}
	}
	return result
}

// CompareJSON compares two JSON byte slices ignoring whitespace differences
func CompareJSON(t *testing.T, got, want []byte) {
	t.Helper()

	var gotJSON, wantJSON interface{}

	if err := json.Unmarshal(got, &gotJSON); err != nil {
		t.Fatalf("failed to unmarshal got JSON: %v", err)
	}

	if err := json.Unmarshal(want, &wantJSON); err != nil {
		t.Fatalf("failed to unmarshal want JSON: %v", err)
	}

	gotBytes, err := json.Marshal(gotJSON)
	if err != nil {
		t.Fatalf("failed to marshal got JSON: %v", err)
	}

	wantBytes, err := json.Marshal(wantJSON)
	if err != nil {
		t.Fatalf("failed to marshal want JSON: %v", err)
	}

	if string(gotBytes) != string(wantBytes) {
		t.Errorf("JSON mismatch:\ngot:  %s\nwant: %s", string(gotBytes), string(wantBytes))
	}
}

// GenerateTestKeyPair generates a test Ed25519 key pair
func GenerateTestKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key pair: %v", err)
	}
	return pub, priv
}

// ErrorContains checks if error contains expected message
func ErrorContains(t *testing.T, err error, expectedMsg string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", expectedMsg)
	}
	if !strings.Contains(err.Error(), expectedMsg) {
		t.Fatalf("expected error containing %q, got %q", expectedMsg, err.Error())
	}
}

// NoError fails the test if err is not nil
func NoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// MustMarshal marshals data to JSON or fails the test
func MustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	return data
}

// MustUnmarshal unmarshals JSON data or fails the test
func MustUnmarshal[T any](t *testing.T, data []byte) T {
	t.Helper()
	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	return result
}

// AssertEqual compares two values for equality
func AssertEqual[T comparable](t *testing.T, got, want T, msgAndArgs ...interface{}) {
	t.Helper()
	if got != want {
		msg := fmt.Sprintf("values not equal:\ngot:  %v\nwant: %v", got, want)
		if len(msgAndArgs) > 0 {
			if format, ok := msgAndArgs[0].(string); ok {
				msg = fmt.Sprintf(format, msgAndArgs[1:]...) + "\n" + msg
			}
		}
		t.Error(msg)
	}
}

// AssertNotEqual compares two values for inequality
func AssertNotEqual[T comparable](t *testing.T, got, want T, msgAndArgs ...interface{}) {
	t.Helper()
	if got == want {
		msg := fmt.Sprintf("values should not be equal: %v", got)
		if len(msgAndArgs) > 0 {
			if format, ok := msgAndArgs[0].(string); ok {
				msg = fmt.Sprintf(format, msgAndArgs[1:]...) + "\n" + msg
			}
		}
		t.Error(msg)
	}
}

// RunTableTest runs a table-driven test
func RunTableTest[T any](t *testing.T, tests []TestCase[T], testFunc func(t *testing.T, tc TestCase[T])) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			defer func() {
				if tt.Cleanup != nil {
					tt.Cleanup(t)
				}
			}()
			testFunc(t, tt)
		})
	}
}

// CreateInvalidJSON creates various types of invalid JSON for testing
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

// Benchmark helper function
func BenchmarkOperation(b *testing.B, operation func()) {
	b.Helper()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		operation()
	}
}

// CreateTestJSON creates test JSON for different metadata types
func CreateTestRootJSON(t *testing.T) []byte {
	t.Helper()

	expiry := time.Now().UTC().Add(24 * time.Hour)

	root := map[string]interface{}{
		"signed": map[string]interface{}{
			"_type":               "root",
			"spec_version":        "1.0.31",
			"version":             1,
			"expires":             expiry.Format(time.RFC3339),
			"consistent_snapshot": true,
			"keys":                map[string]interface{}{},
			"roles": map[string]interface{}{
				"root": map[string]interface{}{
					"keyids":    []string{},
					"threshold": 1,
				},
				"targets": map[string]interface{}{
					"keyids":    []string{},
					"threshold": 1,
				},
				"snapshot": map[string]interface{}{
					"keyids":    []string{},
					"threshold": 1,
				},
				"timestamp": map[string]interface{}{
					"keyids":    []string{},
					"threshold": 1,
				},
			},
		},
		"signatures": []interface{}{},
	}

	data, err := json.Marshal(root)
	if err != nil {
		t.Fatalf("failed to create test root JSON: %v", err)
	}
	return data
}

func CreateTestTargetsJSON(t *testing.T) []byte {
	t.Helper()

	expiry := time.Now().UTC().Add(24 * time.Hour)

	targets := map[string]interface{}{
		"signed": map[string]interface{}{
			"_type":        "targets",
			"spec_version": "1.0.31",
			"version":      1,
			"expires":      expiry.Format(time.RFC3339),
			"targets":      map[string]interface{}{},
		},
		"signatures": []interface{}{},
	}

	data, err := json.Marshal(targets)
	if err != nil {
		t.Fatalf("failed to create test targets JSON: %v", err)
	}
	return data
}

func CreateTestSnapshotJSON(t *testing.T) []byte {
	t.Helper()

	expiry := time.Now().UTC().Add(24 * time.Hour)

	snapshot := map[string]interface{}{
		"signed": map[string]interface{}{
			"_type":        "snapshot",
			"spec_version": "1.0.31",
			"version":      1,
			"expires":      expiry.Format(time.RFC3339),
			"meta": map[string]interface{}{
				"targets.json": map[string]interface{}{
					"version": 1,
				},
			},
		},
		"signatures": []interface{}{},
	}

	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("failed to create test snapshot JSON: %v", err)
	}
	return data
}

func CreateTestTimestampJSON(t *testing.T) []byte {
	t.Helper()

	expiry := time.Now().UTC().Add(24 * time.Hour)

	timestamp := map[string]interface{}{
		"signed": map[string]interface{}{
			"_type":        "timestamp",
			"spec_version": "1.0.31",
			"version":      1,
			"expires":      expiry.Format(time.RFC3339),
			"meta": map[string]interface{}{
				"snapshot.json": map[string]interface{}{
					"version": 1,
				},
			},
		},
		"signatures": []interface{}{},
	}

	data, err := json.Marshal(timestamp)
	if err != nil {
		t.Fatalf("failed to create test timestamp JSON: %v", err)
	}
	return data
}

// HexBytes is a simple type for testing - avoiding import cycles
type HexBytes []byte

func (h HexBytes) String() string {
	return fmt.Sprintf("%x", []byte(h))
}
