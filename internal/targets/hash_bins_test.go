package targets

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func BenchmarkHexEncode1(b *testing.B) {
	for n := 0; n <= b.N; n++ {
		for x := uint64(0); x <= 0xf; x += 1 {
			hexEncode(x, 1)
		}
	}
}

func BenchmarkHexEncode4(b *testing.B) {
	for n := 0; n <= b.N; n++ {
		for x := uint64(0); x <= 0xffff; x += 1 {
			hexEncode(x, 4)
		}
	}
}

func TestHashBin(t *testing.T) {
	h := HashBin{
		First: 0x0,
		Last:  0xf,
	}
	assert.Equal(t, "abc_0-f", h.Name("abc_", 1))
	assert.Equal(t, "abc_0000-000f", h.Name("abc_", 4))
	assert.Equal(t, []string{
		"00", "01", "02", "03", "04", "05", "06", "07",
		"08", "09", "0a", "0b", "0c", "0d", "0e", "0f",
	}, h.Enumerate(2))

	h = HashBin{
		First: 0xcd,
		Last:  0xce,
	}
	assert.Equal(t, "abc_00cd-00ce", h.Name("abc_", 4))
	assert.Equal(t, []string{"00cd", "00ce"}, h.Enumerate(4))

	h = HashBin{
		First: 0x0abc,
		Last:  0xbcde,
	}
	assert.Equal(t, "test_0abc-bcde", h.Name("test_", 4))
}

func TestHashPrefixLength(t *testing.T) {
	assert.Equal(t, 1, HashPrefixLength(0))
	assert.Equal(t, 1, HashPrefixLength(1))
	assert.Equal(t, 1, HashPrefixLength(2))
	assert.Equal(t, 1, HashPrefixLength(3))
	assert.Equal(t, 1, HashPrefixLength(4))
	assert.Equal(t, 2, HashPrefixLength(5))
	assert.Equal(t, 2, HashPrefixLength(6))
	assert.Equal(t, 2, HashPrefixLength(7))
	assert.Equal(t, 2, HashPrefixLength(8))
	assert.Equal(t, 3, HashPrefixLength(9))
	assert.Equal(t, 3, HashPrefixLength(10))
	assert.Equal(t, 3, HashPrefixLength(11))
	assert.Equal(t, 3, HashPrefixLength(12))
}

func TestGenerateHashBins(t *testing.T) {
	tcs := []struct {
		Log2NumBins uint8
		BinNames    []string
	}{
		{0, []string{"0-f"}},
		{1, []string{"0-7", "8-f"}},
		{2, []string{"0-3", "4-7", "8-b", "c-f"}},
		{3, []string{"0-1", "2-3", "4-5", "6-7", "8-9", "a-b", "c-d", "e-f"}},
		{4, []string{
			"0", "1", "2", "3", "4", "5", "6", "7",
			"8", "9", "a", "b", "c", "d", "e", "f",
		}},
		{5, []string{
			"00-07", "08-0f", "10-17", "18-1f", "20-27", "28-2f", "30-37", "38-3f",
			"40-47", "48-4f", "50-57", "58-5f", "60-67", "68-6f", "70-77", "78-7f",
			"80-87", "88-8f", "90-97", "98-9f", "a0-a7", "a8-af", "b0-b7", "b8-bf",
			"c0-c7", "c8-cf", "d0-d7", "d8-df", "e0-e7", "e8-ef", "f0-f7", "f8-ff",
		}},
	}
	for _, tc := range tcs {
		bn := []string{}
		bins := GenerateHashBins(tc.Log2NumBins)
		for _, b := range bins {
			bn = append(bn, b.Name("", HashPrefixLength(tc.Log2NumBins)))
		}
		assert.Equal(t, tc.BinNames, bn, "GenerateHashBins(%v)", tc.Log2NumBins)
	}
}
