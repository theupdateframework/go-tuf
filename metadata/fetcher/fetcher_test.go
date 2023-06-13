// Copyright 2023 VMware, Inc.
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
	"errors"
	"testing"
	"time"

	"github.com/rdimitrov/go-tuf-metadata/metadata"
	"github.com/stretchr/testify/assert"
)

const (
	exampleURL = "https://example.com/metadata/"
	realUrl    = "https://jku.github.io/tuf-demo/metadata/1.root.json"
)

func TestDownloadFileWithExampleUrl(t *testing.T) {
	fetcher := DefaultFetcher{httpUserAgent: ""}

	fetcher.httpUserAgent = "someUserAgent"

	data, err := fetcher.DownloadFile(exampleURL, 34)
	if assert.NotNil(t, err) {
		if assert.IsType(t, metadata.ErrDownloadHTTP{}, err) {
			var checkErr metadata.ErrDownloadHTTP
			if errors.As(err, &checkErr) {
				assert.NotEqual(t, 200, checkErr.StatusCode)
				assert.Equal(t, 404, checkErr.StatusCode)
			}
		}
	}
	assert.Empty(t, data)
}

func TestDownloadFileWithRealURL(t *testing.T) {
	fetcher := DefaultFetcher{httpUserAgent: ""}

	data, err := fetcher.DownloadFile(realUrl, 3000)
	assert.Nil(t, err)
	assert.NotEmpty(t, data)

	now := time.Now().UTC()
	safeExpiry := now.Truncate(time.Second).AddDate(0, 0, 30)
	mdRoot := metadata.Root(safeExpiry)
	err = mdRoot.UnmarshalJSON(data)

	assert.Nil(t, err)
	assert.Equal(t, mdRoot.Signed.Type, metadata.ROOT)
	assert.Equal(t, mdRoot.Signed.Version, int64(1))
	assert.LessOrEqual(t, mdRoot.Signed.SpecVersion, metadata.SPECIFICATION_VERSION)
}
