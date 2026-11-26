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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/theupdateframework/go-tuf/v2/internal/testutils/simulator"
	"github.com/theupdateframework/go-tuf/v2/metadata"
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

// blockingFetcher serves everything from inner except URLs ending in suffix, which block
// until the caller's context is done. It implements fetcher.ContextFetcher.
type blockingFetcher struct {
	inner   fetcher.Fetcher
	suffix  string
	release chan struct{}
}

func newBlockingFetcher(t *testing.T, inner fetcher.Fetcher, suffix string) *blockingFetcher {
	b := &blockingFetcher{inner: inner, suffix: suffix, release: make(chan struct{})}
	// A test that fails because ctx never arrived must not leave the download blocked forever.
	t.Cleanup(func() { close(b.release) })
	return b
}

func (b *blockingFetcher) DownloadFile(urlPath string, maxLength int64, timeout time.Duration) ([]byte, error) {
	return b.DownloadFileContext(context.Background(), urlPath, maxLength)
}

func (b *blockingFetcher) DownloadFileContext(ctx context.Context, urlPath string, maxLength int64) ([]byte, error) {
	if strings.HasSuffix(urlPath, b.suffix) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-b.release:
			return nil, context.Canceled
		}
	}
	return b.inner.DownloadFile(urlPath, maxLength, 0)
}

// returnsWithin runs f and fails the test if it does not return within 10s.
func returnsWithin(t *testing.T, f func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f() }()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("the call did not return after its context expired")
		return nil
	}
}

// GetTargetInfoContext's implicit initial refresh is cancelled by its context.
func TestGetTargetInfoContext_CancelDuringImplicitRefresh(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	cfg, err := repo.GetUpdaterConfig()
	require.NoError(t, err)
	cfg.Fetcher = newBlockingFetcher(t, cfg.Fetcher, "timestamp.json")
	up, err := New(cfg)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	err = returnsWithin(t, func() error {
		_, err := up.GetTargetInfoContext(ctx, "file.txt")
		return err
	})
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// GetTargetInfoContext is cancelled while it downloads a delegated role's metadata.
func TestGetTargetInfoContext_CancelDuringDelegatedRoleDownload(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	delegate(repo, metadata.TARGETS, "role1", "role1/*")
	repo.AddTarget("role1", []byte("content"), "role1/file.txt")
	repo.UpdateSnapshot()
	cfg, err := repo.GetUpdaterConfig()
	require.NoError(t, err)
	cfg.Fetcher = newBlockingFetcher(t, cfg.Fetcher, "role1.json")
	up, err := New(cfg)
	require.NoError(t, err)
	require.NoError(t, up.RefreshContext(t.Context()))

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	err = returnsWithin(t, func() error {
		_, err := up.GetTargetInfoContext(ctx, "role1/file.txt")
		return err
	})
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// DownloadTargetContext is cancelled while it downloads the target file.
func TestDownloadTargetContext_CancelDuringDownload(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	repo.AddTarget(metadata.TARGETS, []byte("content"), "file.txt")
	repo.UpdateSnapshot()
	cfg, err := repo.GetUpdaterConfig()
	require.NoError(t, err)
	cfg.Fetcher = newBlockingFetcher(t, cfg.Fetcher, "file.txt")
	up, err := New(cfg)
	require.NoError(t, err)
	info, err := up.GetTargetInfoContext(t.Context(), "file.txt")
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	err = returnsWithin(t, func() error {
		_, _, err := up.DownloadTargetContext(ctx, info, filepath.Join(t.TempDir(), "file.txt"), "")
		return err
	})
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// A nil context is an error, not a panic, on every context-aware entry point.
func TestContextMethods_NilContextIsAnError(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	repo.AddTarget(metadata.TARGETS, []byte("content"), "file.txt")
	repo.UpdateSnapshot()
	cfg, err := repo.GetUpdaterConfig()
	require.NoError(t, err)
	up, err := New(cfg)
	require.NoError(t, err)
	var nilCtx context.Context // a variable, so linters accept passing it

	var valueErr *metadata.ErrValue
	assert.ErrorAs(t, up.RefreshContext(nilCtx), &valueErr)
	_, err = up.GetTargetInfoContext(nilCtx, "file.txt")
	assert.ErrorAs(t, err, &valueErr)

	info, err := up.GetTargetInfoContext(t.Context(), "file.txt")
	require.NoError(t, err)
	_, _, err = up.DownloadTargetContext(nilCtx, info, filepath.Join(t.TempDir(), "file.txt"), "")
	assert.ErrorAs(t, err, &valueErr)
}

// An already-cancelled context is reported even when no download would happen: on
// cached targets metadata, and in UnsafeLocalMode.
func TestContextMethods_CancelledContextOnCachedAndLocalPaths(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	repo.AddTarget(metadata.TARGETS, []byte("content"), "file.txt")
	repo.UpdateSnapshot()
	cfg, err := repo.GetUpdaterConfig()
	require.NoError(t, err)
	up, err := New(cfg)
	require.NoError(t, err)
	_, err = up.GetTargetInfoContext(t.Context(), "file.txt") // refreshes and persists metadata
	require.NoError(t, err)

	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = up.GetTargetInfoContext(cancelled, "file.txt")
	assert.ErrorIs(t, err, context.Canceled, "cached targets metadata")

	localCfg, err := repo.GetUnsafeUpdaterConfig()
	require.NoError(t, err)
	local, err := New(localCfg)
	require.NoError(t, err)
	assert.ErrorIs(t, local.RefreshContext(cancelled), context.Canceled, "UnsafeLocalMode")
	require.NoError(t, local.RefreshContext(t.Context()), "the local metadata is complete")
}
