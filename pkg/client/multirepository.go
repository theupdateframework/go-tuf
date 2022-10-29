package client

type Name string

// For each repository, its key name is the directory where files, including
// the root metadata file, are cached, and its value is a list of URLs where
// files may be downloaded. See: https://github.com/theupdateframework/taps/blob/master/tap4.md
type Repository struct {
	keyName Name
	urls    []string
}

// For each set of targets, specify a list of repositories where files may be
// downloaded. The entries listed first will be considered first.
type Mapping struct {
	paths        []string
	repositories []Name
	threshold    int
	terminating  bool
}

type Map struct {
	repositories []string
	mapping      []Mapping
}
