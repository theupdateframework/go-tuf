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
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// Fetcher interface
type Fetcher interface {
	DownloadFile(urlPath string, maxLength int64, timeout time.Duration) ([]byte, error)
}

func NewDefaultFetcher() DefaultFetcher {
	return NewDefaultFetcherWithConfig(time.Second*15, "", 0, 0)
}

func NewDefaultFetcherWithConfig(timeout time.Duration, httpUserAgent string, backoffInterval time.Duration, retryCount uint64) DefaultFetcher {
	return DefaultFetcher{
		httpUserAgent: httpUserAgent,
		timeout:       timeout,
		backoffCfg: BackoffConfig{
			RetryInterval: backoffInterval,
			RetryCount:    retryCount,
		},
	}
}

type BackoffConfig struct {
	RetryInterval time.Duration
	RetryCount    uint64
}

// DefaultFetcher implements Fetcher
type DefaultFetcher struct {
	httpUserAgent string
	timeout       time.Duration
	backoffCfg    BackoffConfig
}

func (d *DefaultFetcher) SetHTTPUserAgent(httpUserAgent string) {
	d.httpUserAgent = httpUserAgent
}

// DownloadFile downloads a file from urlPath, errors out if it failed,
// its length is larger than maxLength or the timeout is reached.
func (d *DefaultFetcher) DownloadFile(urlPath string, maxLength int64, timeout time.Duration) ([]byte, error) {
	// If the timeout parameter is set, use it, otherwise use the default field value
	var tm time.Duration
	if timeout != 0 {
		tm = timeout
	} else {
		tm = d.timeout
	}
	client := &http.Client{Timeout: tm}
	req, err := http.NewRequest("GET", urlPath, nil)
	if err != nil {
		return nil, err
	}
	// Use in case of multiple sessions.
	if d.httpUserAgent != "" {
		req.Header.Set("User-Agent", d.httpUserAgent)
	}

	var data []byte
	bo := backoff.NewConstantBackOff(d.backoffCfg.RetryInterval)
	err = backoff.Retry(func() error {
		// Execute the request.
		res, err := client.Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		// Handle HTTP status codes.
		if res.StatusCode != http.StatusOK {
			return &metadata.ErrDownloadHTTP{StatusCode: res.StatusCode, URL: urlPath}
		}
		var length int64
		// Get content length from header (might not be accurate, -1 or not set).
		if header := res.Header.Get("Content-Length"); header != "" {
			length, err = strconv.ParseInt(header, 10, 0)
			if err != nil {
				return err
			}
			// Error if the reported size is greater than what is expected.
			if length > maxLength {
				return &metadata.ErrDownloadLengthMismatch{Msg: fmt.Sprintf("download failed for %s, length %d is larger than expected %d", urlPath, length, maxLength)}
			}
		}
		// Although the size has been checked above, use a LimitReader in case
		// the reported size is inaccurate, or size is -1 which indicates an
		// unknown length. We read maxLength + 1 in order to check if the read data
		// surpassed our set limit.
		data, err := io.ReadAll(io.LimitReader(res.Body, maxLength+1))
		if err != nil {
			return err
		}
		// Error if the reported size is greater than what is expected.
		length = int64(len(data))
		if length > maxLength {
			return &metadata.ErrDownloadLengthMismatch{Msg: fmt.Sprintf("download failed for %s, length %d is larger than expected %d", urlPath, length, maxLength)}
		}

		return nil
	}, backoff.WithMaxRetries(bo, d.backoffCfg.RetryCount))

	if err != nil {
		return nil, err
	}

	return data, nil
}
