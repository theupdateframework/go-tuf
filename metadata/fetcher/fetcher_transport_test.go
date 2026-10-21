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

package fetcher

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// countingTransport answers every request successfully and records how many
// requests reached it, so a test can tell which transport was used.
type countingTransport struct {
	name  string
	calls int
}

func (t *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("{}")),
	}, nil
}

// pinDefaultClientTransport installs a known transport on http.DefaultClient
// and restores the original one when the test finishes.
func pinDefaultClientTransport(t *testing.T) *countingTransport {
	t.Helper()
	original := http.DefaultClient.Transport
	t.Cleanup(func() { http.DefaultClient.Transport = original })
	pinned := &countingTransport{name: "http.DefaultClient"}
	http.DefaultClient.Transport = pinned
	return pinned
}

func TestSetTransportKeepsDefaultClientUntouched(t *testing.T) {
	pinned := pinDefaultClientTransport(t)

	ours := &countingTransport{name: "fetcher"}
	f := NewDefaultFetcher()
	assert.NoError(t, f.SetTransport(ours))

	assert.Same(t, pinned, http.DefaultClient.Transport)

	data, err := f.DownloadFile("http://127.0.0.1/metadata/1.root.json", 512000, 0)
	assert.NoError(t, err)
	assert.Equal(t, []byte("{}"), data)
	assert.Equal(t, 1, ours.calls)
	assert.Equal(t, 0, pinned.calls)

	res, err := http.DefaultClient.Get("http://127.0.0.1/unrelated")
	assert.NoError(t, err)
	res.Body.Close()
	assert.Equal(t, 1, pinned.calls)
	assert.Equal(t, 1, ours.calls)
}

func TestNewFetcherWithRoundTripperKeepsDefaultClientUntouched(t *testing.T) {
	pinned := pinDefaultClientTransport(t)

	ours := &countingTransport{name: "fetcher"}
	f := NewDefaultFetcher().NewFetcherWithRoundTripper(ours)

	assert.Same(t, pinned, http.DefaultClient.Transport)

	data, err := f.DownloadFile("http://127.0.0.1/metadata/1.root.json", 512000, 0)
	assert.NoError(t, err)
	assert.Equal(t, []byte("{}"), data)
	assert.Equal(t, 1, ours.calls)
	assert.Equal(t, 0, pinned.calls)
}
