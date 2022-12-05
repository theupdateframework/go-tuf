package updater

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rdimitrov/ngo-tuf/metadata"
	"github.com/rdimitrov/ngo-tuf/metadata/trustedmetadata"
)

type UpdaterConfig struct {
	MaxRootRotations      int64
	MaxDelegations        int64
	RootMaxLength         int64
	TimestampMaxLength    int64
	SnapshotMaxLength     int64
	TargetsMaxLength      int64
	PrefixTargetsWithHash bool
}
type Updater struct {
	metadataDir     string
	metadataBaseUrl string
	targetDir       string
	targetBaseUrl   string
	trusted         *trustedmetadata.TrustedMetadata
	config          *UpdaterConfig
	// fetcher
	// config
}

// New creates a new “Updater“ instance and loads trusted root metadata.
func New(metadataDir, metadataBaseUrl, targetDir, targetBaseUrl string) (*Updater, error) {
	rootBytes, err := loadLocalMetadata(metadata.ROOT)
	if err != nil {
		return nil, err
	}
	trustedMetadataSet, err := trustedmetadata.New(rootBytes)
	if err != nil {
		return nil, err
	}
	// validate input
	metadataBaseUrl = ensureTrailingSlash(metadataBaseUrl)
	if len(targetBaseUrl) > 0 {
		targetBaseUrl = ensureTrailingSlash(targetBaseUrl)
	}

	return &Updater{
		metadataDir:     metadataDir,
		metadataBaseUrl: metadataBaseUrl,
		targetDir:       targetDir,
		targetBaseUrl:   targetBaseUrl,
		trusted:         trustedMetadataSet,
		config:          NewConfig(),
	}, nil
}

func loadLocalMetadata(name string) ([]byte, error) {
	name = fmt.Sprintf("%s.json", name)
	in, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("error opening metadata file - %s", name)
	}
	defer in.Close()
	data, err := io.ReadAll(in)
	if err != nil {
		return nil, fmt.Errorf("error reading metadata bytes from file - %s", name)
	}
	return data, nil
}

// NewConfig creates a new UpdaterConfig instance used by the Updater to
// store configuration
func NewConfig() *UpdaterConfig {
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

// ensureTrailingSlash ensures url ends with a slash
func ensureTrailingSlash(url string) string {
	if strings.HasSuffix(url, "/") {
		return url
	}
	return url + "/"
}
