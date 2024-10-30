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

package repository

import (
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// Type struct for storing metadata
type Type struct {
	root      *metadata.Metadata[metadata.RootType]
	snapshot  *metadata.Metadata[metadata.SnapshotType]
	timestamp *metadata.Metadata[metadata.TimestampType]
	targets   map[string]*metadata.Metadata[metadata.TargetsType]
}

// New creates an empty repository instance
func New() *Type {
	return &Type{
		targets: map[string]*metadata.Metadata[metadata.TargetsType]{},
	}
}

// Root returns metadata of type Root
func (r *Type) Root() *metadata.Metadata[metadata.RootType] {
	return r.root
}

// SetRoot sets metadata of type Root
func (r *Type) SetRoot(meta *metadata.Metadata[metadata.RootType]) {
	r.root = meta
}

// Snapshot returns metadata of type Snapshot
func (r *Type) Snapshot() *metadata.Metadata[metadata.SnapshotType] {
	return r.snapshot
}

// SetSnapshot sets metadata of type Snapshot
func (r *Type) SetSnapshot(meta *metadata.Metadata[metadata.SnapshotType]) {
	r.snapshot = meta
}

// Timestamp returns metadata of type Timestamp
func (r *Type) Timestamp() *metadata.Metadata[metadata.TimestampType] {
	return r.timestamp
}

// SetTimestamp sets metadata of type Timestamp
func (r *Type) SetTimestamp(meta *metadata.Metadata[metadata.TimestampType]) {
	r.timestamp = meta
}

// Targets returns metadata of type Targets
func (r *Type) Targets(name string) *metadata.Metadata[metadata.TargetsType] {
	return r.targets[name]
}

// SetTargets sets metadata of type Targets
func (r *Type) SetTargets(name string, meta *metadata.Metadata[metadata.TargetsType]) {
	r.targets[name] = meta
}
