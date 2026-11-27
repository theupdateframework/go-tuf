//go:build tuf_client

// Copyright 2026 The Update Framework Authors
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

package clientprofile_test

import (
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestClientProfileOmitsSigningAndSDKDependencies(t *testing.T) {
	if _, present := reflect.TypeOf(metadata.Root()).MethodByName("Sign"); present {
		t.Fatal("publisher signing method is present in the tuf_client profile")
	}

	out, err := exec.Command(
		"go", "list", "-tags", "tuf_client", "-deps",
		"github.com/theupdateframework/go-tuf/v2/metadata/updater",
		"github.com/theupdateframework/go-tuf/v2/metadata/multirepo",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps failed: %v\n%s", err, string(out))
	}

	deps := string(out)
	for _, forbidden := range []string{
		"github.com/sigstore/",
		"google.golang.org/protobuf",
		"github.com/google/go-containerregistry",
		"github.com/secure-systems-lab/go-securesystemslib/encrypted",
	} {
		if strings.Contains(deps, forbidden) {
			t.Fatalf("tuf_client dependency graph still includes %q", forbidden)
		}
	}
}
