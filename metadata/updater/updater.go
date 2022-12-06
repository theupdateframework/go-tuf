package updater

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/rdimitrov/ngo-tuf/metadata"
	"github.com/rdimitrov/ngo-tuf/metadata/config"
	"github.com/rdimitrov/ngo-tuf/metadata/trustedmetadata"
)

type Updater struct {
	metadataDir     string
	metadataBaseUrl string
	targetDir       string
	targetBaseUrl   string
	trusted         *trustedmetadata.TrustedMetadata
	config          *config.UpdaterConfig
	// fetcher
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
		config:          config.New(),
	}, nil
}

// downloadMetadata download a metadata file and return it as bytes
func (up *Updater) downloadMetadata(roleName string, length int, version string) ([]byte, error) {
	var urlPath string
	roleName = url.QueryEscape(roleName)
	if version == "" {
		urlPath = fmt.Sprint("%s%s.json", up.metadataBaseUrl, roleName)
	} else {
		urlPath = fmt.Sprint("%s%s.%s.json", up.metadataBaseUrl, version, roleName)
	}
	_ = urlPath
	// download file with size length from path
	return nil, nil
}

func loadLocalMetadata(roleName string) ([]byte, error) {
	roleName = fmt.Sprintf("%s.json", url.QueryEscape(roleName))
	in, err := os.Open(roleName)
	if err != nil {
		return nil, fmt.Errorf("error opening metadata file - %s", roleName)
	}
	defer in.Close()
	data, err := io.ReadAll(in)
	if err != nil {
		return nil, fmt.Errorf("error reading metadata bytes from file - %s", roleName)
	}
	return data, nil
}

// ensureTrailingSlash ensures url ends with a slash
func ensureTrailingSlash(url string) string {
	if strings.HasSuffix(url, "/") {
		return url
	}
	return url + "/"
}
