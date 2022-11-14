package repo

import (
	"github.com/rdimitrov/ngo-tuf/metadata"
)

// struct for storing various metadata
type repository struct {
	root      *metadata.Metadata[metadata.RootType]
	snapshot  *metadata.Metadata[metadata.SnapshotType]
	timestamp *metadata.Metadata[metadata.TimestampType]
	targets   map[string]*metadata.Metadata[metadata.TargetsType]
}

// New creates an empty repository instance
func New() *repository {
	return &repository{
		targets: map[string]*metadata.Metadata[metadata.TargetsType]{},
	}
}

// Root returns metadata of type Root
func (r *repository) Root() *metadata.Metadata[metadata.RootType] {
	return r.root
}

// SetRoot sets metadata of type Root
func (r *repository) SetRoot(meta *metadata.Metadata[metadata.RootType]) {
	r.root = meta
}

// Snapshot returns metadata of type Snapshot
func (r *repository) Snapshot() *metadata.Metadata[metadata.SnapshotType] {
	return r.snapshot
}

// SetSnapshot sets metadata of type Snapshot
func (r *repository) SetSnapshot(meta *metadata.Metadata[metadata.SnapshotType]) {
	r.snapshot = meta
}

// Timestamp returns metadata of type Timestamp
func (r *repository) Timestamp() *metadata.Metadata[metadata.TimestampType] {
	return r.timestamp
}

// SetTimestamp sets metadata of type Timestamp
func (r *repository) SetTimestamp(meta *metadata.Metadata[metadata.TimestampType]) {
	r.timestamp = meta
}

// Targets returns metadata of type Targets
func (r *repository) Targets(name string) *metadata.Metadata[metadata.TargetsType] {
	return r.targets[name]
}

// SetTargets sets metadata of type Targets
func (r *repository) SetTargets(name string, meta *metadata.Metadata[metadata.TargetsType]) {
	r.targets[name] = meta
}
