// Copyright 2022-2023 VMware, Inc.
//
// This product is licensed to you under the BSD-2 license (the "License").
// You may not use this product except in compliance with the BSD-2 License.
// This product may include a number of subcomponents with separate copyright
// notices and license terms. Your use of these subcomponents is subject to
// the terms and conditions of the subcomponent's license, as noted in the
// LICENSE file.
//
// SPDX-License-Identifier: BSD-2-Clause

package fetcher

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/rdimitrov/go-tuf-metadata/metadata"
)

// Fetcher interface
type Fetcher interface {
	DownloadFile(urlPath string, maxLength int64, timeout time.Duration) ([]byte, error)
}

// DefaultFetcher implements Fetcher
type DefaultFetcher struct {
	httpUserAgent string
}

// DownloadFile downloads a file from urlPath, errors out if it failed,
// its length is larger than maxLength or the timeout is reached.
func (d *DefaultFetcher) DownloadFile(urlPath string, maxLength int64, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("GET", urlPath, nil)
	if err != nil {
		return nil, err
	}
	// Use in case of multiple sessions.
	if d.httpUserAgent != "" {
		req.Header.Set("User-Agent", d.httpUserAgent)
	}
	// Execute the request.
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	// Handle HTTP status codes.
	if res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusForbidden || res.StatusCode != http.StatusOK {
		return nil, metadata.ErrDownloadHTTP{StatusCode: res.StatusCode, URL: urlPath}
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
			return nil, metadata.ErrDownloadLengthMismatch{Msg: fmt.Sprintf("download failed for %s, length %d is larger than expected %d", urlPath, length, maxLength)}
		}
	}
	// Although the size has been checked above, use a LimitReader in case
	// the reported size is inaccurate, or size is -1 which indicates an
	// unknown length. We read maxLength + 1 in order to check if the read data
	// surpased our set limit.
	data, err := io.ReadAll(io.LimitReader(res.Body, maxLength+1))
	if err != nil {
		return nil, err
	}
	// Error if the reported size is greater than what is expected.
	length = int64(len(data))
	if length > maxLength {
		return nil, metadata.ErrDownloadLengthMismatch{Msg: fmt.Sprintf("download failed for %s, length %d is larger than expected %d", urlPath, length, maxLength)}
	}

	return data, nil
}
