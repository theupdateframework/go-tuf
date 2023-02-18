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
	"io"
	"net/http"

	"github.com/rdimitrov/go-tuf-metadata/metadata"
)

// Fetcher interface
type Fetcher interface {
	DownloadFile(urlPath string, maxLength int64) ([]byte, error)
}

// Default fetcher
type DefaultFetcher struct {
	httpUserAgent string
}

// DownloadFile downloads a file from urlPath, errors out if it failed or its length is larger than maxLength
func (d *DefaultFetcher) DownloadFile(urlPath string, maxLength int64) ([]byte, error) {
	client := http.DefaultClient
	req, err := http.NewRequest("GET", urlPath, nil)
	if err != nil {
		return nil, err
	}
	// use in case of multiple sessions
	if d.httpUserAgent != "" {
		req.Header.Set("User-Agent", d.httpUserAgent)
	}
	// execute the request
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	// handle HTTP status codes
	if res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusForbidden || res.StatusCode != http.StatusOK {
		return nil, metadata.ErrDownloadHTTP{StatusCode: res.StatusCode, URL: urlPath}
	}
	// TODO: handle content length correctly as we should not rely on the Content-Length header
	// // get content length
	// length, err := strconv.ParseInt(res.Header.Get("Content-Length"), 10, 0)
	// if err != nil {
	// 	return nil, err
	// }
	// // error if the reported size is greater than what is expected
	// if length > maxLength {
	// 	return nil, metadata.ErrDownloadLengthMismatch{Msg: fmt.Sprintf("download failed for %s, length %d is larger than expected %d", urlPath, length, maxLength)}
	// }
	// although the size has been checked above, use a LimitReader in case
	// the reported size is inaccurate, or size is -1 which indicates an
	// unknown length
	return io.ReadAll(io.LimitReader(res.Body, maxLength))
}
