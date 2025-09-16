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

package metadata

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	mathrand "math/rand"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
)

// BenchmarkMetadataCreation benchmarks metadata creation operations
func BenchmarkMetadataCreation(b *testing.B) {
	expiry := time.Now().UTC().Add(24 * time.Hour)

	benchmarks := []struct {
		name string
		fn   func() any
	}{
		{
			name: "Root",
			fn:   func() any { return Root(expiry) },
		},
		{
			name: "Targets",
			fn:   func() any { return Targets(expiry) },
		},
		{
			name: "Snapshot",
			fn:   func() any { return Snapshot(expiry) },
		},
		{
			name: "Timestamp",
			fn:   func() any { return Timestamp(expiry) },
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = bm.fn()
			}
		})
	}
}

// BenchmarkMetadataToBytes benchmarks serialization to bytes
func BenchmarkMetadataToBytes(b *testing.B) {
	expiry := time.Now().UTC().Add(24 * time.Hour)

	root := Root(expiry)
	targets := Targets(expiry)
	snapshot := Snapshot(expiry)
	timestamp := Timestamp(expiry)

	// Add some data to make benchmarks more realistic
	root.Signed.Keys["test-key"] = &Key{
		Type:   "ed25519",
		Scheme: "ed25519",
		Value:  KeyVal{PublicKey: "test-public-key"},
	}

	targets.Signed.Targets["test-file"] = &TargetFiles{
		Length: 1024,
		Hashes: Hashes{
			"sha256": HexBytes("abcdef1234567890"),
		},
	}

	benchmarks := []struct {
		name     string
		metadata func() ([]byte, error)
	}{
		{
			name: "Root-Compact",
			metadata: func() ([]byte, error) {
				return root.ToBytes(true)
			},
		},
		{
			name: "Root-Pretty",
			metadata: func() ([]byte, error) {
				return root.ToBytes(false)
			},
		},
		{
			name: "Targets-Compact",
			metadata: func() ([]byte, error) {
				return targets.ToBytes(true)
			},
		},
		{
			name: "Targets-Pretty",
			metadata: func() ([]byte, error) {
				return targets.ToBytes(false)
			},
		},
		{
			name: "Snapshot-Compact",
			metadata: func() ([]byte, error) {
				return snapshot.ToBytes(true)
			},
		},
		{
			name: "Timestamp-Compact",
			metadata: func() ([]byte, error) {
				return timestamp.ToBytes(true)
			},
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := bm.metadata()
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkMetadataFromBytes benchmarks deserialization from bytes
func BenchmarkMetadataFromBytes(b *testing.B) {
	// Pre-generate test data
	expiry := time.Now().UTC().Add(24 * time.Hour)

	root := Root(expiry)
	targets := Targets(expiry)
	snapshot := Snapshot(expiry)
	timestamp := Timestamp(expiry)

	rootData, _ := root.ToBytes(false)
	targetsData, _ := targets.ToBytes(false)
	snapshotData, _ := snapshot.ToBytes(false)
	timestampData, _ := timestamp.ToBytes(false)

	benchmarks := []struct {
		name string
		data []byte
		fn   func([]byte) error
	}{
		{
			name: "Root",
			data: rootData,
			fn: func(data []byte) error {
				_, err := Root().FromBytes(data)
				return err
			},
		},
		{
			name: "Targets",
			data: targetsData,
			fn: func(data []byte) error {
				_, err := Targets().FromBytes(data)
				return err
			},
		},
		{
			name: "Snapshot",
			data: snapshotData,
			fn: func(data []byte) error {
				_, err := Snapshot().FromBytes(data)
				return err
			},
		},
		{
			name: "Timestamp",
			data: timestampData,
			fn: func(data []byte) error {
				_, err := Timestamp().FromBytes(data)
				return err
			},
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				err := bm.fn(bm.data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkSignatureOperations benchmarks signature creation and verification
func BenchmarkSignatureOperations(b *testing.B) {
	// Generate test key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	// Create test metadata
	root := Root()
	keyID := "test-key-id"
	root.Signed.Keys[keyID] = &Key{
		Type:   "ed25519",
		Scheme: "ed25519",
		Value:  KeyVal{PublicKey: string(pub)},
	}
	root.Signed.Roles[ROOT].KeyIDs = []string{keyID}

	b.Run("Sign", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Create a fresh copy for each iteration
			testRoot := Root()
			testRoot.Signed = root.Signed

			// Create signer from private key
			signer, err := signature.LoadSigner(priv, crypto.Hash(0))
			if err != nil {
				b.Fatal(err)
			}

			_, err = testRoot.Sign(signer)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	// Sign once for verification benchmarks
	signer, err := signature.LoadSigner(priv, crypto.Hash(0))
	if err != nil {
		b.Fatal(err)
	}
	_, err = root.Sign(signer)
	if err != nil {
		b.Fatal(err)
	}

	// Pre-generate test data

}

// BenchmarkJSONOperations benchmarks raw JSON operations for comparison
func BenchmarkJSONOperations(b *testing.B) {
	expiry := time.Now().UTC().Add(24 * time.Hour)
	root := Root(expiry)

	// Add some complexity
	for i := 0; i < 10; i++ {
		keyID := generateRandomString(64)
		root.Signed.Keys[keyID] = &Key{
			Type:   "ed25519",
			Scheme: "ed25519",
			Value:  KeyVal{PublicKey: string(generateRandomBytes(32))},
		}
	}

	data, err := json.Marshal(root)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("JSON-Marshal", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := json.Marshal(root)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("JSON-Unmarshal", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var result Metadata[RootType]
			err := json.Unmarshal(data, &result)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkHexBytesOperations benchmarks HexBytes operations
func BenchmarkHexBytesOperations(b *testing.B) {
	testData := [][]byte{
		[]byte("small"),
		make([]byte, 256),   // medium
		make([]byte, 8192),  // large
		make([]byte, 65536), // very large
	}

	// Fill test data with random bytes
	for _, data := range testData {
		_, _ = rand.Read(data)
	}

	for i, data := range testData {
		size := []string{"Small", "Medium", "Large", "VeryLarge"}[i]

		b.Run("Marshal-"+size, func(b *testing.B) {
			hexBytes := HexBytes(data)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := json.Marshal(hexBytes)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run("Unmarshal-"+size, func(b *testing.B) {
			hexBytes := HexBytes(data)
			jsonData, err := json.Marshal(hexBytes)
			if err != nil {
				b.Fatal(err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var result HexBytes
				err := json.Unmarshal(jsonData, &result)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkComplexStructures benchmarks operations on complex metadata structures
func BenchmarkComplexStructures(b *testing.B) {
	// Create complex targets metadata with many files
	targets := Targets()

	// Add many target files
	for i := 0; i < 1000; i++ {
		filename := generateRandomString(20) + ".txt"
		targets.Signed.Targets[filename] = &TargetFiles{
			Length: int64(i + 1000),
			Hashes: Hashes{
				"sha256": HexBytes(generateRandomString(64)),
				"sha512": HexBytes(generateRandomString(128)),
			},
		}
	}

	// Add delegations
	targets.Signed.Delegations = &Delegations{
		Keys:  make(map[string]*Key),
		Roles: make([]DelegatedRole, 0),
	}

	for i := 0; i < 50; i++ {
		keyID := generateRandomString(64)
		targets.Signed.Delegations.Keys[keyID] = &Key{
			Type:   "ed25519",
			Scheme: "ed25519",
			Value:  KeyVal{PublicKey: string(generateRandomBytes(32))},
		}

		targets.Signed.Delegations.Roles = append(targets.Signed.Delegations.Roles, DelegatedRole{
			Name:        generateRandomString(15),
			KeyIDs:      []string{keyID},
			Threshold:   1,
			Terminating: i%2 == 1,
			Paths:       []string{generateRandomString(10) + "/*"},
		})
	}

	b.Run("ComplexTargets-ToBytes", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := targets.ToBytes(true)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	// Pre-serialize for FromBytes benchmark
	complexData, err := targets.ToBytes(true)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("ComplexTargets-FromBytes", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := Targets().FromBytes(complexData)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkMemoryAllocations benchmarks memory usage patterns
func BenchmarkMemoryAllocations(b *testing.B) {
	b.Run("MetadataCreation-Allocs", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			root := Root()
			_ = root
		}
	})

	b.Run("Serialization-Allocs", func(b *testing.B) {
		root := Root()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			data, err := root.ToBytes(true)
			if err != nil {
				b.Fatal(err)
			}
			_ = data
		}
	})

	b.Run("Deserialization-Allocs", func(b *testing.B) {
		root := Root()
		data, err := root.ToBytes(true)
		if err != nil {
			b.Fatal(err)
		}

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := Root().FromBytes(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkConcurrentOperations benchmarks concurrent access patterns
func BenchmarkConcurrentOperations(b *testing.B) {
	root := Root()
	data, err := root.ToBytes(true)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("ConcurrentDeserialization", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := Root().FromBytes(data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	})

	b.Run("ConcurrentSerialization", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				testRoot := Root()
				_, err := testRoot.ToBytes(true)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	})
}

// Helper functions to avoid import cycles
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[mathrand.Intn(len(charset))]
	}
	return string(b)
}

func generateRandomBytes(length int) []byte {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return b
}
