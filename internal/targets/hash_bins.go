package targets

import (
	"strconv"
	"strings"
)

// hexEncode formats x as a hex string, left padded with zeros to padWidth.
func hexEncode(x uint64, padWidth int) string {
	// Benchmarked to be more than 10x faster than padding with Sprintf.
	s := strconv.FormatUint(x, 16)
	if len(s) >= padWidth {
		return s
	}
	return strings.Repeat("0", padWidth-len(s)) + s
}

// HashBin represents a hex prefix range. First should be less than Last.
type HashBin struct {
	First uint64
	Last  uint64
}

// Name returns the of the role that signs for the HashBin.
func (b HashBin) Name(prefix string, padWidth int) string {
	if b.First == b.Last {
		return prefix + hexEncode(b.First, padWidth)
	}

	return prefix + hexEncode(b.First, padWidth) + "-" + hexEncode(b.Last, padWidth)
}

// Enumerate returns a slice of hash prefixes in the range from First to Last.
func (b HashBin) Enumerate(padWidth int) []string {
	n := int(b.Last - b.First + 1)
	ret := make([]string, int(n))

	x := b.First
	for i := 0; i < n; i++ {
		ret[i] = hexEncode(x, padWidth)
		x++
	}

	return ret
}

// HashPrefixLength returns the width of hash prefixes if there are
// 2^(log2NumBins) hash bins.
func HashPrefixLength(log2NumBins uint8) int {
	if log2NumBins == 0 {
		// Hash prefix of "" is represented equivalently as "0-f".
		return 1
	}

	// ceil(log2NumBins / 4.0)
	return int((log2NumBins-1)/4) + 1
}

// GenerateHashBins returns a slice of length 2^(log2NumBins) that partitions
// the space of path hashes into HashBin ranges.
func GenerateHashBins(log2NumBins uint8) []HashBin {
	numBins := uint64(1) << log2NumBins

	// numPrefixes = 16^(HashPrefixLength(log2NumBins))
	numPrefixes := uint64(1) << (4 * HashPrefixLength(log2NumBins))

	p := make([]HashBin, numBins)

	first := uint64(0)
	interval := numPrefixes / numBins
	last := first + interval - 1
	for i := uint64(0); i < numBins; i++ {
		p[i] = HashBin{
			First: first,
			Last:  last,
		}
		first += interval
		last += interval
	}

	return p
}
