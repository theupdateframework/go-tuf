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
	tcs := []struct {
		hb           *HashBin
		roleName     string
		hashPrefixes []string
	}{
		{
			hb: &HashBin{
				rolePrefix:  "abc_",
				hexDigitLen: 1,
				first:       0x0,
				last:        0x7,
			},
			roleName: "abc_0-7",
			hashPrefixes: []string{
				"0", "1", "2", "3", "4", "5", "6", "7",
			},
		},
		{
			hb: &HashBin{
				rolePrefix:  "abc_",
				hexDigitLen: 2,
				first:       0x0,
				last:        0xf,
			},
			roleName: "abc_00-0f",
			hashPrefixes: []string{
				"00", "01", "02", "03", "04", "05", "06", "07",
				"08", "09", "0a", "0b", "0c", "0d", "0e", "0f",
			},
		},
		{
			hb: &HashBin{
				rolePrefix:  "cba_",
				hexDigitLen: 4,
				first:       0xcd,
				last:        0xcf,
			},
			roleName:     "cba_00cd-00cf",
			hashPrefixes: []string{"00cd", "00ce", "00cf"},
		},
		{
			hb: &HashBin{
				rolePrefix:  "cba_",
				hexDigitLen: 3,
				first:       0xc1,
				last:        0xc1,
			},
			roleName:     "cba_0c1",
			hashPrefixes: []string{"0c1"},
		},
	}

	for i, tc := range tcs {
		assert.Equalf(t, tc.roleName, tc.hb.RoleName(), "test case %v: RoleName()", i)
		assert.Equalf(t, tc.hashPrefixes, tc.hb.HashPrefixes(), "test case %v: HashPrefixes()", i)
	}
}

func TestHashBins(t *testing.T) {
	tcs := []struct {
		bitLen    int
		roleNames []string
	}{
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
	for i, tc := range tcs {
		got := []string{}
		hbs, err := NewHashBins("", tc.bitLen)
		assert.NoError(t, err)
		n := hbs.NumBins()
		for i := uint64(0); i < n; i += 1 {
			hb := hbs.GetBin(i)
			got = append(got, hb.RoleName())
		}
		assert.Equalf(t, tc.roleNames, got, "test case %v", i)
	}

	_, err := NewHashBins("", 0)
	assert.Error(t, err)
	_, err = NewHashBins("", 33)
	assert.Error(t, err)
}
