package sets

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStringSliceToSet(t *testing.T) {
	assert.Equal(t,
		map[string]struct{}{
			"a": {},
			"b": {},
			"c": {},
		},
		StringSliceToSet([]string{"a", "c", "b", "c", "b"}))
}

func TestStringSetToSlice(t *testing.T) {
	assert.ElementsMatch(t,
		[]string{"a", "b", "c"},
		StringSetToSlice(map[string]struct{}{
			"a": {},
			"b": {},
			"c": {},
		}),
	)
}

func TestDeduplicateStrings(t *testing.T) {
	assert.ElementsMatch(t,
		[]string{"a", "b", "c"},
		DeduplicateStrings([]string{"a", "c", "b", "c", "b"}),
	)
}
