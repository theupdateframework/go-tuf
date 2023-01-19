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

package metadata

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRootDefaultValues(t *testing.T) {
	// without setting expiration
	root := Root()
	assert.NotNil(t, root)
	assert.GreaterOrEqual(t, []time.Time{time.Now().UTC()}[0], root.Signed.Expires)

	// setting expiration
	expire := time.Now().AddDate(0, 0, 2).UTC()
	root = Root(expire)
	assert.NotNil(t, root)
	assert.Equal(t, expire, root.Signed.Expires)

	// Type
	assert.Equal(t, ROOT, root.Signed.Type)

	// SpecVersion
	assert.Equal(t, SPECIFICATION_VERSION, root.Signed.SpecVersion)

	// Version
	assert.Equal(t, int64(1), root.Signed.Version)

	// Threshold and KeyIDs for Roles
	for _, role := range []string{ROOT, SNAPSHOT, TARGETS, TIMESTAMP} {
		assert.Equal(t, 1, root.Signed.Roles[role].Threshold)
		assert.Equal(t, []string{}, root.Signed.Roles[role].KeyIDs)
	}

	// Keys
	assert.Equal(t, map[string]*Key{}, root.Signed.Keys)

	// Consistent snapshot
	assert.True(t, root.Signed.ConsistentSnapshot)

}
