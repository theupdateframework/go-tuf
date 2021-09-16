package signer

import (
	"sort"

	"github.com/theupdateframework/go-tuf/sign"
)

// ByIDs implements sort.Interface for []sign.Signer based on the sorted
// IDs() for each Signer. This facilitates deterministic order of signatures,
// which prevents tests that use fixtures from being flaky.
type ByIDs []sign.Signer

func (b ByIDs) Len() int {
	return len(b)
}

func (b ByIDs) Swap(i, j int) {
	b[i], b[j] = b[j], b[i]
}

func (b ByIDs) Less(i, j int) bool {
	ids := b[i].IDs()
	iIDs := make([]string, len(ids))
	copy(iIDs, ids)
	sort.Strings(iIDs)

	ids = b[j].IDs()
	jIDs := make([]string, len(ids))
	copy(jIDs, ids)
	sort.Strings(jIDs)

	minLen := len(iIDs)
	if len(jIDs) < minLen {
		minLen = len(jIDs)
	}

	// Compare iIDs[:minLen] to jIDs[:minLen] element-wise.
	for c := 0; c < minLen; c++ {
		if iIDs[c] == jIDs[c] {
			continue
		}
		return iIDs[c] < jIDs[c]
	}

	// iIDs[:minLen] is equal to jIDs[:minLen], so sort based on length.
	return len(iIDs) < len(jIDs)
}
