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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// UpdaterTestCase defines a single table-driven updater test scenario.
// It is intentionally decoupled from the updater package to avoid import cycles.
type UpdaterTestCase struct {
	// Name is the subtest name passed to t.Run.
	Name string

	// Desc is an optional human-readable description logged with t.Logf.
	Desc string

	// WantErr indicates that the action under test must return a non-nil error.
	WantErr bool

	// WantErrType is an error value compared with errors.Is. Only checked when
	// WantErr is true.
	WantErrType error

	// WantErrMsg is a substring that must appear in the error message. Only
	// checked when WantErr is true.
	WantErrMsg string

	// RefTime is a reference time injected into updater tests (e.g. for
	// expiry testing).
	RefTime time.Time

	// UseUnsafeMode enables UnsafeLocalMode for this test case.
	UseUnsafeMode bool
}

// CheckError validates error expectations for a single UpdaterTestCase.
// Call it immediately after the operation under test.
func CheckError(t *testing.T, tc UpdaterTestCase, err error) {
	t.Helper()

	if tc.WantErr {
		if err == nil {
			t.Errorf("CheckError(%q): expected error, got nil", tc.Name)
			return
		}
		if tc.WantErrType != nil && !errors.Is(err, tc.WantErrType) {
			t.Errorf("CheckError(%q): expected error type %T, got %T: %v",
				tc.Name, tc.WantErrType, err, err)
		}
		if tc.WantErrMsg != "" && !strings.Contains(err.Error(), tc.WantErrMsg) {
			t.Errorf("CheckError(%q): expected error message containing %q, got %q",
				tc.Name, tc.WantErrMsg, err.Error())
		}
	} else if err != nil {
		t.Errorf("CheckError(%q): unexpected error: %v", tc.Name, err)
	}
}

// AssertFilesExist asserts that each role in roles has a corresponding
// "<role>.json" file in metadataDir.
func AssertFilesExist(t *testing.T, metadataDir string, roles []string) {
	t.Helper()
	for _, role := range roles {
		path := filepath.Join(metadataDir, fmt.Sprintf("%s.json", role))
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("AssertFilesExist: expected %s.json not found in %s", role, metadataDir)
		}
	}
}

// AssertFilesExact asserts that metadataDir contains exactly the files named
// "<role>.json" for each role in roles — no more, no fewer.
func AssertFilesExact(t *testing.T, metadataDir string, roles []string) {
	t.Helper()

	expected := make(map[string]bool, len(roles))
	for _, role := range roles {
		expected[fmt.Sprintf("%s.json", role)] = true
	}

	entries, err := os.ReadDir(metadataDir)
	if err != nil {
		t.Fatalf("AssertFilesExact: ReadDir(%q): %v", metadataDir, err)
	}

	actual := make(map[string]bool, len(entries))
	for _, e := range entries {
		actual[e.Name()] = true
	}

	for name := range expected {
		if !actual[name] {
			t.Errorf("AssertFilesExact: expected file %q not found in %s", name, metadataDir)
		}
	}
	for name := range actual {
		if !expected[name] {
			t.Errorf("AssertFilesExact: unexpected file %q found in %s", name, metadataDir)
		}
	}
}

// TrustedMetadataTestCase defines a single table-driven test for TrustedMetadata
// operations. The Setup function returns the raw bytes to operate on; Action
// receives those bytes and returns an error (or nil on success).
type TrustedMetadataTestCase struct {
	Name        string
	Desc        string
	Setup       func(t *testing.T) []byte
	Action      func(t *testing.T, data []byte) error
	WantErr     bool
	WantErrType error
	WantErrMsg  string
}

// RunTrustedMetadataTests executes a slice of TrustedMetadataTestCase entries
// as subtests.
func RunTrustedMetadataTests(t *testing.T, tests []TrustedMetadataTestCase) {
	t.Helper()
	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.Desc != "" {
				t.Logf("desc: %s", tc.Desc)
			}

			var data []byte
			if tc.Setup != nil {
				data = tc.Setup(t)
			}

			err := tc.Action(t, data)

			if tc.WantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
					return
				}
				if tc.WantErrType != nil && !errors.Is(err, tc.WantErrType) {
					t.Errorf("expected error type %T, got %T: %v",
						tc.WantErrType, err, err)
				}
				if tc.WantErrMsg != "" && !strings.Contains(err.Error(), tc.WantErrMsg) {
					t.Errorf("expected error containing %q, got %q",
						tc.WantErrMsg, err.Error())
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
