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
	"encoding/json"
	"fmt"
	"maps"
	"math/rand/v2"
	"strings"
	"testing"
	"time"
)

// FuzzDataGenerator produces deterministic pseudo-random data for fuzz seeds.
// Use [NewFuzzDataGenerator] to construct one with a fixed seed for
// reproducible seed corpora, or use 0 for a randomly seeded source.
type FuzzDataGenerator struct {
	rng *rand.Rand
}

// NewFuzzDataGenerator returns a generator backed by a PCG source seeded with
// seed1 and seed2. For a single uint64 seed, pass the same value twice.
func NewFuzzDataGenerator(seed1, seed2 uint64) *FuzzDataGenerator {
	return &FuzzDataGenerator{
		rng: rand.New(rand.NewPCG(seed1, seed2)),
	}
}

// GenerateRandomString returns a random alphanumeric string of the given length.
func (f *FuzzDataGenerator) GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[f.rng.IntN(len(charset))]
	}
	return string(b)
}

// GenerateRandomBytes returns a slice of n pseudo-random bytes.
func (f *FuzzDataGenerator) GenerateRandomBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(f.rng.IntN(256))
	}
	return b
}

// GenerateRandomInt returns a non-negative pseudo-random int in [0, max).
func (f *FuzzDataGenerator) GenerateRandomInt(max int) int {
	return f.rng.IntN(max)
}

// GenerateRandomTime returns a pseudo-random time between 2020 and 2030 (UTC).
func (f *FuzzDataGenerator) GenerateRandomTime() time.Time {
	start := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2030, 12, 31, 23, 59, 59, 0, time.UTC)
	delta := end.Sub(start)
	return start.Add(time.Duration(f.rng.Int64N(int64(delta))))
}

// GenerateRandomJSON returns a JSON object that resembles TUF metadata but
// with random field values.
func (f *FuzzDataGenerator) GenerateRandomJSON() []byte {
	data := map[string]any{
		"signed": map[string]any{
			"_type":        f.GenerateRandomString(f.rng.IntN(20) + 1),
			"version":      f.rng.IntN(1000),
			"spec_version": f.GenerateRandomString(10),
			"expires":      f.GenerateRandomTime().Format(time.RFC3339),
		},
		"signatures": []map[string]any{
			{
				"keyid": f.GenerateRandomString(64),
				"sig":   f.GenerateRandomString(128),
			},
		},
	}
	out, _ := json.Marshal(data)
	return out
}

// GenerateCorruptedJSON returns one of several varieties of intentionally
// malformed JSON, chosen pseudo-randomly.
func (f *FuzzDataGenerator) GenerateCorruptedJSON() []byte {
	corruptors := []func() []byte{
		// Truncated JSON
		func() []byte {
			valid := f.GenerateRandomJSON()
			if len(valid) > 10 {
				return valid[:len(valid)/2]
			}
			return valid
		},
		// Replaced colons with random strings
		func() []byte {
			return []byte(strings.ReplaceAll(string(f.GenerateRandomJSON()), ":", f.GenerateRandomString(5)))
		},
		// Deeply nested object
		func() []byte {
			depth := f.rng.IntN(100) + 1
			var sb strings.Builder
			for i := range depth {
				fmt.Fprintf(&sb, `{"level%d":`, i)
			}
			sb.WriteString(`"value"`)
			for range depth {
				sb.WriteByte('}')
			}
			return []byte(sb.String())
		},
		// Very long string
		func() []byte {
			long := f.GenerateRandomString(f.rng.IntN(10000) + 1000)
			return fmt.Appendf(nil, `{"long_string":"%s"}`, long)
		},
		// Arbitrary bytes injected into a JSON string
		func() []byte {
			payload := f.GenerateRandomBytes(50)
			prefix := []byte(`{"test":"`)
			suffix := []byte(`"}`)
			return append(prefix, append(payload, suffix...)...)
		},
	}
	return corruptors[f.rng.IntN(len(corruptors))]()
}

// GenerateRandomMetadataFields returns a map of random values for common TUF
// metadata fields.
func (f *FuzzDataGenerator) GenerateRandomMetadataFields() map[string]any {
	return map[string]any{
		"version":      f.rng.IntN(1_000_000),
		"spec_version": f.GenerateRandomString(f.rng.IntN(20) + 1),
		"expires":      f.GenerateRandomTime().Format(time.RFC3339),
		"type":         f.GenerateRandomString(f.rng.IntN(20) + 1),
		"length":       f.rng.IntN(1_000_000),
		"hashes": map[string]string{
			"sha256": f.GenerateRandomString(64),
			"sha512": f.GenerateRandomString(128),
		},
		"keyids":    []string{f.GenerateRandomString(64), f.GenerateRandomString(64)},
		"threshold": f.rng.IntN(10) + 1,
		"custom": map[string]any{
			"random_field": f.GenerateRandomString(100),
			"number":       f.rng.IntN(1000),
		},
	}
}

// GenerateRandomSignature returns a random TUF-like signature map.
func (f *FuzzDataGenerator) GenerateRandomSignature() map[string]any {
	return map[string]any{
		"keyid": f.GenerateRandomString(64),
		"sig":   f.GenerateRandomString(f.rng.IntN(200) + 50),
	}
}

// GenerateRandomKey returns a random TUF-like key map.
func (f *FuzzDataGenerator) GenerateRandomKey() map[string]any {
	keyTypes := []string{"ed25519", "rsa", "ecdsa", "unknown"}
	schemes := []string{"ed25519", "rsa-pss-sha256", "ecdsa-sha2-nistp256", "unknown"}
	return map[string]any{
		"keytype": keyTypes[f.rng.IntN(len(keyTypes))],
		"scheme":  schemes[f.rng.IntN(len(schemes))],
		"keyval": map[string]any{
			"public": f.GenerateRandomString(f.rng.IntN(500) + 50),
		},
	}
}

// CreateFuzzTestMetadata returns a JSON-encoded TUF metadata structure for
// metadataType ("root", "targets", "snapshot", "timestamp") with random field
// values. Useful as fuzz seed input.
func (f *FuzzDataGenerator) CreateFuzzTestMetadata(metadataType string) []byte {
	base := map[string]any{
		"signed": map[string]any{
			"_type": metadataType,
		},
		"signatures": []any{f.GenerateRandomSignature()},
	}

	signed := base["signed"].(map[string]any)
	maps.Copy(signed, f.GenerateRandomMetadataFields())

	switch metadataType {
	case "root":
		signed["keys"] = map[string]any{
			f.GenerateRandomString(64): f.GenerateRandomKey(),
		}
		signed["roles"] = map[string]any{
			"root": map[string]any{
				"keyids":    []string{f.GenerateRandomString(64)},
				"threshold": f.rng.IntN(5) + 1,
			},
		}
		signed["consistent_snapshot"] = f.rng.IntN(2) == 1
	case "targets":
		signed["targets"] = map[string]any{
			f.GenerateRandomString(20): f.GenerateRandomMetadataFields()["hashes"],
		}
	case "snapshot":
		signed["meta"] = map[string]any{
			"targets.json": map[string]any{
				"version": f.rng.IntN(1000),
				"hashes":  f.GenerateRandomMetadataFields()["hashes"],
				"length":  f.rng.IntN(10000),
			},
		}
	case "timestamp":
		signed["meta"] = map[string]any{
			"snapshot.json": map[string]any{
				"version": f.rng.IntN(1000),
				"hashes":  f.GenerateRandomMetadataFields()["hashes"],
				"length":  f.rng.IntN(10000),
			},
		}
	}

	out, _ := json.Marshal(base)
	return out
}

// FuzzMetadataOperations registers seeds and runs f.Fuzz against operation.
// The operation must never panic regardless of input; errors are acceptable.
//
// Seed data is taken from [BuildRootJSON], [BuildTargetsJSON],
// [BuildSnapshotJSON], and [BuildTimestampJSON] (no *testing.T required) plus
// a selection of corrupted JSON variants.
func FuzzMetadataOperations(f *testing.F, operation func(data []byte) error) {
	f.Helper()

	// Add valid metadata as seeds using the builder functions (no *testing.T).
	f.Add(BuildRootJSON())
	f.Add(BuildTargetsJSON())
	f.Add(BuildSnapshotJSON())
	f.Add(BuildTimestampJSON())

	// Add edge cases.
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte("null"))
	f.Add([]byte("[]"))

	// Add some corrupted-data seeds.
	gen := NewFuzzDataGenerator(0xdeadbeef, 0xcafebabe)
	for range 10 {
		f.Add(gen.GenerateCorruptedJSON())
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("operation panicked with input %q: %v", data, r)
			}
		}()
		_ = operation(data)
	})
}
