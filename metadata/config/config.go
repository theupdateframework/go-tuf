package config

type UpdaterConfig struct {
	MaxRootRotations      int64
	MaxDelegations        int64
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
