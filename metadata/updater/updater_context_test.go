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

package updater

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/theupdateframework/go-tuf/v2/internal/testutils/simulator"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

// hangingMirror accepts every request and never answers until the client goes away.
func hangingMirror(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	return srv
}

// RefreshContext returns once its context expires, even while the DefaultFetcher is
// blocked on a mirror that accepted the connection and never answers (#835).
func TestRefreshContext_CancelAbortsAHangingMirror(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	cfg, err := repo.GetUpdaterConfig()
	require.NoError(t, err)
	cfg.RemoteMetadataURL = hangingMirror(t).URL + "/metadata/"
	cfg.Fetcher = fetcher.NewDefaultFetcher()
	up, err := New(cfg)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- up.RefreshContext(ctx) }()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(10 * time.Second):
		t.Fatal("RefreshContext did not return after its context expired")
	}
}

// plainFetcher implements only Fetcher, as third-party fetchers written before
// ContextFetcher do.
type plainFetcher struct{ calls int }

func (p *plainFetcher) DownloadFile(string, int64, time.Duration) ([]byte, error) {
	p.calls++
	return nil, context.Canceled
}

// A Fetcher without DownloadFileContext keeps working through the context-aware
// methods, and an already-cancelled context stops the updater before it calls it.
func TestRefreshContext_PlainFetcherStillUsedAndCancelledContextSkipsIt(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	cfg, err := repo.GetUpdaterConfig()
	require.NoError(t, err)
	pf := &plainFetcher{}
	cfg.Fetcher = pf
	up, err := New(cfg)
	require.NoError(t, err)

	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	assert.ErrorIs(t, up.RefreshContext(cancelled), context.Canceled)
	assert.Zero(t, pf.calls, "a cancelled context reached the fetcher")

	_ = up.RefreshContext(t.Context())
	assert.Positive(t, pf.calls, "a Fetcher without DownloadFileContext was not called")
}
