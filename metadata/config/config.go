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

package config

type UpdaterConfig struct {
	MaxRootRotations      int64
	MaxDelegations        int
	RootMaxLength         int64
	TimestampMaxLength    int64
	SnapshotMaxLength     int64
	TargetsMaxLength      int64
	PrefixTargetsWithHash bool
}

// New creates a new UpdaterConfig instance used by the Updater to
// store configuration
func New() *UpdaterConfig {
	return &UpdaterConfig{
		MaxRootRotations:      32,
		MaxDelegations:        32,
		RootMaxLength:         512000,  // bytes
		TimestampMaxLength:    16384,   // bytes
		SnapshotMaxLength:     2000000, // bytes
		TargetsMaxLength:      5000000, // bytes
		PrefixTargetsWithHash: true,
	}
}
