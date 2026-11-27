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

package fetcher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// httpClient interface allows us to either provide a live http.Client
// or a mock implementation for testing purposes
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Fetcher interface
type Fetcher interface {
	// DownloadFile downloads a file from the provided URL, reading
	// up to maxLength of bytes before it aborts.
	// The timeout argument is deprecated and not used. To configure
	// the timeout (or retries), modify the fetcher instead. For the
	// DefaultFetcher the underlying HTTP client can be substituted.
	DownloadFile(urlPath string, maxLength int64, _ time.Duration) ([]byte, error)
}

// ContextFetcher is a Fetcher whose downloads can be cancelled. The updater uses
// DownloadFileContext when the configured Fetcher implements it.
type ContextFetcher interface {
	Fetcher
	// DownloadFileContext is DownloadFile bound to ctx: cancelling ctx aborts the
	// request and any retries.
	DownloadFileContext(ctx context.Context, urlPath string, maxLength int64) ([]byte, error)
}

// DefaultFetcher implements Fetcher and ContextFetcher
type DefaultFetcher struct {
	//  httpClient configuration
	httpUserAgent string
	client        httpClient
	// retry logic configuration
	retryOptions []backoff.RetryOption
}

func (d *DefaultFetcher) SetHTTPUserAgent(httpUserAgent string) {
	d.httpUserAgent = httpUserAgent
}

// DownloadFile downloads a file from urlPath, errors out if it failed or
// its length is larger than maxLength. The timeout argument is unused, and with
// the default HTTP client the request is not bounded in time: use
// DownloadFileContext to cancel it.
func (d *DefaultFetcher) DownloadFile(urlPath string, maxLength int64, _ time.Duration) ([]byte, error) {
	return d.DownloadFileContext(context.Background(), urlPath, maxLength)
}

// DownloadFileContext downloads a file from urlPath like DownloadFile, and aborts the
// request and any retries when ctx is cancelled.
func (d *DefaultFetcher) DownloadFileContext(ctx context.Context, urlPath string, maxLength int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlPath, nil)
	if err != nil {
		return nil, err
	}
	// backoff.Retry runs the operation once before it looks at ctx, so a custom
	// httpClient would otherwise still be called with an already-cancelled context.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Use in case of multiple sessions.
	if d.httpUserAgent != "" {
		req.Header.Set("User-Agent", d.httpUserAgent)
	}

	// For backwards compatibility, if the client is nil, use the default client.
	if d.client == nil {
		d.client = http.DefaultClient
	}

	operation := func() ([]byte, error) {
		// Execute the request.
		res, err := d.client.Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
		// Handle HTTP status codes.
		if res.StatusCode != http.StatusOK {
			return nil, &metadata.ErrDownloadHTTP{StatusCode: res.StatusCode, URL: urlPath}
		}
		var length int64
		// Get content length from header (might not be accurate, -1 or not set).
		if header := res.Header.Get("Content-Length"); header != "" {
			length, err = strconv.ParseInt(header, 10, 0)
			if err != nil {
				return nil, err
			}
			// Error if the reported size is greater than what is expected.
			if length > maxLength {
				return nil, &metadata.ErrDownloadLengthMismatch{Msg: fmt.Sprintf("download failed for %s, length %d is larger than expected %d", urlPath, length, maxLength)}
			}
		}
		// Although the size has been checked above, use a LimitReader in case
		// the reported size is inaccurate, or size is -1 which indicates an
		// unknown length. We read maxLength + 1 in order to check if the read data
		// surpassed our set limit.
		data, err := io.ReadAll(io.LimitReader(res.Body, maxLength+1))
		if err != nil {
			return nil, err
		}
		// Error if the reported size is greater than what is expected.
		length = int64(len(data))
		if length > maxLength {
			return nil, &metadata.ErrDownloadLengthMismatch{Msg: fmt.Sprintf("download failed for %s, length %d is larger than expected %d", urlPath, length, maxLength)}
		}

		return data, nil
	}
	data, err := backoff.Retry(ctx, operation, d.retryOptions...)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func NewDefaultFetcher() *DefaultFetcher {
	return &DefaultFetcher{
		client: http.DefaultClient,
		// default to attempting the HTTP request once
		retryOptions: []backoff.RetryOption{backoff.WithMaxTries(1)},
	}
}

func (f *DefaultFetcher) inheritedHTTPUserAgent() string {
	if f != nil {
		return f.httpUserAgent
	}
	return ""
}

func (f *DefaultFetcher) inheritedRetryOptions() []backoff.RetryOption {
	if f != nil && len(f.retryOptions) > 0 {
		return slices.Clone(f.retryOptions)
	}
	return []backoff.RetryOption{backoff.WithMaxTries(1)}
}

// NewFetcherWithHTTPClient creates a new DefaultFetcher with a custom httpClient
func (f *DefaultFetcher) NewFetcherWithHTTPClient(hc httpClient) *DefaultFetcher {
	return &DefaultFetcher{
		httpUserAgent: f.inheritedHTTPUserAgent(),
		client:        hc,
		retryOptions:  f.inheritedRetryOptions(),
	}
}

// NewFetcherWithRoundTripper creates a new DefaultFetcher with a custom RoundTripper
// The function will create a default http.Client and replace the transport with the provided RoundTripper implementation
func (f *DefaultFetcher) NewFetcherWithRoundTripper(rt http.RoundTripper) *DefaultFetcher {
	return &DefaultFetcher{
		httpUserAgent: f.inheritedHTTPUserAgent(),
		client:        &http.Client{Transport: rt},
		retryOptions:  f.inheritedRetryOptions(),
	}
}

func (f *DefaultFetcher) SetHTTPClient(hc httpClient) {
	f.client = hc
}

func (f *DefaultFetcher) SetTransport(rt http.RoundTripper) error {
	hc, ok := f.client.(*http.Client)
	if !ok {
		return fmt.Errorf("fetcher is not type fetcher.DefaultFetcher")
	}
	// The client may be http.DefaultClient, which is shared with the rest of
	// the process, so copy it rather than setting the transport in place.
	client := *hc
	client.Transport = rt
	f.client = &client
	return nil
}

func (f *DefaultFetcher) SetRetry(retryInterval time.Duration, retryCount uint) {
	constantBackOff := backoff.WithBackOff(backoff.NewConstantBackOff(retryInterval))
	maxTryCount := backoff.WithMaxTries(retryCount)
	f.SetRetryOptions(constantBackOff, maxTryCount)
}

func (f *DefaultFetcher) SetRetryOptions(retryOptions ...backoff.RetryOption) {
	f.retryOptions = retryOptions
}
