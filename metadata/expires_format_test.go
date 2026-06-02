// Copyright 2024 The Update Framework Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
//
// SPDX-License-Identifier: Apache-2.0
//

package metadata

import (
	"encoding/json"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// secondPrecisionUTC matches the TUF spec date/time format for "expires":
// an ISO 8601 / RFC 3339 timestamp in UTC, truncated to whole seconds with
// a trailing Z and no fractional-second component.
var secondPrecisionUTC = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)

// expiresFromJSON pulls the raw "expires" string out of a marshaled signed body.
func expiresFromJSON(t *testing.T, data []byte) string {
	t.Helper()
	var dict map[string]any
	if err := json.Unmarshal(data, &dict); err != nil {
		t.Fatalf("unmarshal signed body: %v", err)
	}
	v, ok := dict["expires"]
	if !ok {
		t.Fatalf("no expires field in %s", string(data))
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("expires is not a string: %T (%v)", v, v)
	}
	return s
}

// TestExpiresMarshalSecondPrecision verifies that every role type serializes
// "expires" with whole-second UTC precision (YYYY-MM-DDTHH:MM:SSZ), per the TUF
// spec, even when the in-memory time.Time carries sub-second precision.
func TestExpiresMarshalSecondPrecision(t *testing.T) {
	// A time with sub-second precision (100 nanoseconds). Marshaling a raw
	// time.Time would emit "2030-08-15T14:30:45.0000001Z".
	subSecond := time.Date(2030, 8, 15, 14, 30, 45, 100, time.UTC)
	wantExpires := "2030-08-15T14:30:45Z"

	cases := []struct {
		name string
		body json.Marshaler
	}{
		{"root", Root(subSecond).Signed},
		{"snapshot", Snapshot(subSecond).Signed},
		{"timestamp", Timestamp(subSecond).Signed},
		{"targets", Targets(subSecond).Signed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tc.body.MarshalJSON()
			assert.NoError(t, err)

			got := expiresFromJSON(t, data)
			assert.Regexp(t, secondPrecisionUTC, got,
				"expires must be whole-second UTC per the TUF spec, got %q", got)
			assert.Equal(t, wantExpires, got)
		})
	}
}

// TestExpiresMarshalUnmarshalRoundTrip confirms that the second-precision
// formatting still round-trips: parsing the formatted output back yields the
// truncated time, and re-marshaling is stable.
func TestExpiresMarshalUnmarshalRoundTrip(t *testing.T) {
	subSecond := time.Date(2030, 8, 15, 14, 30, 45, 100, time.UTC)
	truncated := time.Date(2030, 8, 15, 14, 30, 45, 0, time.UTC)

	root := Root(subSecond)
	data, err := root.Signed.MarshalJSON()
	assert.NoError(t, err)

	var parsed RootType
	assert.NoError(t, parsed.UnmarshalJSON(data))
	assert.True(t, parsed.Expires.Equal(truncated),
		"round-tripped expires %v should equal %v", parsed.Expires, truncated)

	// Re-marshaling the parsed value is stable and still second-precision.
	data2, err := parsed.MarshalJSON()
	assert.NoError(t, err)
	assert.Equal(t, "2030-08-15T14:30:45Z", expiresFromJSON(t, data2))
}
