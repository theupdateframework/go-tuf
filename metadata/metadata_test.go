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
	meta := Root()
	assert.NotNil(t, meta)
	assert.GreaterOrEqual(t, []time.Time{time.Now().UTC()}[0], meta.Signed.Expires)

	// setting expiration
	expire := time.Now().AddDate(0, 0, 2).UTC()
	meta = Root(expire)
	assert.NotNil(t, meta)
	assert.Equal(t, expire, meta.Signed.Expires)

	// Type
	assert.Equal(t, ROOT, meta.Signed.Type)

	// SpecVersion
	assert.Equal(t, SPECIFICATION_VERSION, meta.Signed.SpecVersion)

	// Version
	assert.Equal(t, int64(1), meta.Signed.Version)

	// Threshold and KeyIDs for Roles
	for _, role := range []string{ROOT, SNAPSHOT, TARGETS, TIMESTAMP} {
		assert.Equal(t, 1, meta.Signed.Roles[role].Threshold)
		assert.Equal(t, []string{}, meta.Signed.Roles[role].KeyIDs)
	}

	// Keys
	assert.Equal(t, map[string]*Key{}, meta.Signed.Keys)

	// Consistent snapshot
	assert.True(t, meta.Signed.ConsistentSnapshot)

	// Signatures
	assert.Equal(t, []Signature{}, meta.Signatures)
}

func TestSnapshotDefaultValues(t *testing.T) {
	// without setting expiration
	meta := Snapshot()
	assert.NotNil(t, meta)
	assert.GreaterOrEqual(t, []time.Time{time.Now().UTC()}[0], meta.Signed.Expires)

	// setting expiration
	expire := time.Now().AddDate(0, 0, 2).UTC()
	meta = Snapshot(expire)
	assert.NotNil(t, meta)
	assert.Equal(t, expire, meta.Signed.Expires)

	// Type
	assert.Equal(t, SNAPSHOT, meta.Signed.Type)

	// SpecVersion
	assert.Equal(t, SPECIFICATION_VERSION, meta.Signed.SpecVersion)

	// Version
	assert.Equal(t, int64(1), meta.Signed.Version)

	// Targets meta
	assert.Equal(t, map[string]MetaFiles{"targets.json": {Version: 1}}, meta.Signed.Meta)

	// Signatures
	assert.Equal(t, []Signature{}, meta.Signatures)
}

func TestTimestampDefaultValues(t *testing.T) {
	// without setting expiration
	meta := Timestamp()
	assert.NotNil(t, meta)
	assert.GreaterOrEqual(t, []time.Time{time.Now().UTC()}[0], meta.Signed.Expires)

	// setting expiration
	expire := time.Now().AddDate(0, 0, 2).UTC()
	meta = Timestamp(expire)
	assert.NotNil(t, meta)
	assert.Equal(t, expire, meta.Signed.Expires)

	// Type
	assert.Equal(t, TIMESTAMP, meta.Signed.Type)

	// SpecVersion
	assert.Equal(t, SPECIFICATION_VERSION, meta.Signed.SpecVersion)

	// Version
	assert.Equal(t, int64(1), meta.Signed.Version)

	// Snapshot meta
	assert.Equal(t, map[string]MetaFiles{"snapshot.json": {Version: 1}}, meta.Signed.Meta)

	// Signatures
	assert.Equal(t, []Signature{}, meta.Signatures)
}

func TestTargetsDefaultValues(t *testing.T) {
	// without setting expiration
	meta := Targets()
	assert.NotNil(t, meta)
	assert.GreaterOrEqual(t, []time.Time{time.Now().UTC()}[0], meta.Signed.Expires)

	// setting expiration
	expire := time.Now().AddDate(0, 0, 2).UTC()
	meta = Targets(expire)
	assert.NotNil(t, meta)
	assert.Equal(t, expire, meta.Signed.Expires)

	// Type
	assert.Equal(t, TARGETS, meta.Signed.Type)

	// SpecVersion
	assert.Equal(t, SPECIFICATION_VERSION, meta.Signed.SpecVersion)

	// Version
	assert.Equal(t, int64(1), meta.Signed.Version)

	// Target files
	assert.Equal(t, map[string]TargetFiles{}, meta.Signed.Targets)

	// Signatures
	assert.Equal(t, []Signature{}, meta.Signatures)
}

func TestIsDelegatedPath(t *testing.T) {
	type pathMatch struct {
		Pattern    []string
		TargetPath string
		Expected   bool
	}
	// As per - https://theupdateframework.github.io/specification/latest/#pathpattern
	matches := []pathMatch{
		// a PATHPATTERN of "targets/*.tgz" would match file paths "targets/foo.tgz" and "targets/bar.tgz", but not "targets/foo.txt".
		{
			Pattern:    []string{"targets/*.tgz"},
			TargetPath: "targets/foo.tgz",
			Expected:   true,
		},
		{
			Pattern:    []string{"targets/*.tgz"},
			TargetPath: "targets/bar.tgz",
			Expected:   true,
		},
		{
			Pattern:    []string{"targets/*.tgz"},
			TargetPath: "targets/foo.txt",
			Expected:   false,
		},
		// a PATHPATTERN of "foo-version-?.tgz" matches "foo-version-2.tgz" and "foo-version-a.tgz", but not "foo-version-alpha.tgz".
		{
			Pattern:    []string{"foo-version-?.tgz"},
			TargetPath: "foo-version-2.tgz",
			Expected:   true,
		},
		{
			Pattern:    []string{"foo-version-?.tgz"},
			TargetPath: "foo-version-a.tgz",
			Expected:   true,
		},
		{
			Pattern:    []string{"foo-version-?.tgz"},
			TargetPath: "foo-version-alpha.tgz",
			Expected:   false,
		},
		// a PATHPATTERN of "*.tgz" would match "foo.tgz" and "bar.tgz", but not "targets/foo.tgz"
		{
			Pattern:    []string{"*.tgz"},
			TargetPath: "foo.tgz",
			Expected:   true,
		},
		{
			Pattern:    []string{"*.tgz"},
			TargetPath: "bar.tgz",
			Expected:   true,
		},
		{
			Pattern:    []string{"*.tgz"},
			TargetPath: "targets/foo.tgz",
			Expected:   false,
		},
		// a PATHPATTERN of "foo.tgz" would match only "foo.tgz"
		{
			Pattern:    []string{"foo.tgz"},
			TargetPath: "foo.tgz",
			Expected:   true,
		},
		{
			Pattern:    []string{"foo.tgz"},
			TargetPath: "foosy.tgz",
			Expected:   false,
		},
	}
	for _, match := range matches {
		role := &DelegatedRole{
			Paths: match.Pattern,
		}
		ok, err := role.IsDelegatedPath(match.TargetPath)
		assert.Equal(t, match.Expected, ok)
		assert.Nil(t, err)
	}
}
