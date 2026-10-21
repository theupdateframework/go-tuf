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

package multirepo

import (
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/theupdateframework/go-tuf/v2/internal/testutils/simulator"
)

// serveSimulator serves a simulated TUF repository over HTTP and returns the
// metadata URL to use for it.
func serveSimulator(t *testing.T) (string, []byte) {
	t.Helper()
	sim := simulator.NewRepository()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := sim.DownloadFile(r.URL.Path, math.MaxInt64, 0)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/metadata", sim.SignedRoots[0]
}

// TestRefreshContinuesPastFailingRepository checks that one repository that
// cannot be refreshed does not stop the other repositories from being
// refreshed. Map iteration order is random, so the check is repeated to make
// sure the failing repository is visited first at least once.
func TestRefreshContinuesPastFailingRepository(t *testing.T) {
	goodA, rootA := serveSimulator(t)
	goodB, rootB := serveSimulator(t)

	// a server that fails every request
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(broken.Close)
	// the broken repository is given a valid root so that only Refresh fails
	_, rootBroken := serveSimulator(t)

	mapJSON := fmt.Sprintf(`{
		"repositories": {
			"good-a": [%q],
			"good-b": [%q],
			"broken": [%q]
		},
		"mapping": [
			{
				"paths": ["*"],
				"repositories": ["good-a", "good-b", "broken"],
				"threshold": 2,
				"terminating": true
			}
		]
	}`, goodA, goodB, broken.URL+"/metadata")

	for i := 0; i < 20; i++ {
		cfg, err := NewConfig([]byte(mapJSON), map[string][]byte{
			"good-a": rootA,
			"good-b": rootB,
			"broken": rootBroken,
		})
		if err != nil {
			t.Fatalf("NewConfig() failed: %v", err)
		}
		cfg.LocalMetadataDir = t.TempDir()
		cfg.LocalTargetsDir = t.TempDir()

		client, err := New(cfg)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		err = client.Refresh()
		if err == nil {
			t.Fatal("Refresh() should report the repository that failed to refresh")
		}
		if !strings.Contains(err.Error(), `"broken"`) {
			t.Errorf("Refresh() error should name the failing repository, got: %v", err)
		}
		for _, name := range []string{"good-a", "good-b"} {
			if client.TUFClients[name].GetTrustedMetadataSet().Timestamp == nil {
				t.Fatalf("iteration %d: repository %q was not refreshed because another repository failed", i, name)
			}
		}
	}
}
