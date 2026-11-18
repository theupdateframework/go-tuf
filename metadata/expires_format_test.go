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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// expiresFromJSON pulls the raw "expires" string out of marshaled metadata so
// the assertions below are about the bytes on the wire rather than the
// in-memory time.Time.
func expiresFromJSON(t *testing.T, data []byte) string {
	t.Helper()
	var outer struct {
		Signed struct {
			Expires string `json:"expires"`
		} `json:"signed"`
	}
	assert.NoError(t, json.Unmarshal(data, &outer))
	return outer.Signed.Expires
}

// The TUF specification writes "expires" as an RFC 3339 timestamp in UTC with
// second precision. encoding/json uses RFC3339Nano for a time.Time, so a value
// carrying nanoseconds would otherwise be serialized as
// "2030-01-01T00:00:00.0000001Z".
func TestConstructorsTruncateExpiresToSeconds(t *testing.T) {
	expires := time.Date(2030, 1, 1, 0, 0, 0, 100, time.UTC)
	const want = "2030-01-01T00:00:00Z"

	root, err := Root(expires).MarshalJSON()
	assert.NoError(t, err)
	assert.Equal(t, want, expiresFromJSON(t, root))

	snapshot, err := Snapshot(expires).MarshalJSON()
	assert.NoError(t, err)
	assert.Equal(t, want, expiresFromJSON(t, snapshot))

	targets, err := Targets(expires).MarshalJSON()
	assert.NoError(t, err)
	assert.Equal(t, want, expiresFromJSON(t, targets))

	timestamp, err := Timestamp(expires).MarshalJSON()
	assert.NoError(t, err)
	assert.Equal(t, want, expiresFromJSON(t, timestamp))
}

// A non-UTC expiry is normalized to UTC as well as truncated.
func TestConstructorsNormalizeExpiresToUTC(t *testing.T) {
	zone := time.FixedZone("UTC+2", 2*60*60)
	root, err := Root(time.Date(2030, 1, 1, 2, 0, 0, 500, zone)).MarshalJSON()
	assert.NoError(t, err)
	assert.Equal(t, "2030-01-01T00:00:00Z", expiresFromJSON(t, root))
}

// Truncation deliberately does not happen in MarshalJSON. Verification
// re-marshals parsed metadata to recover the bytes that were signed, so
// reformatting there would change those bytes and invalidate signatures over
// existing metadata whose expires carries sub-second precision. Metadata that
// arrives with nanoseconds must round-trip unchanged.
func TestParsedExpiresRoundTripsUnchanged(t *testing.T) {
	const original = "2030-08-15T14:30:45.0000001Z"

	root := Root()
	raw := []byte(`{"signatures":[],"signed":{"_type":"root","spec_version":"1.0.31","version":1,` +
		`"expires":"` + original + `","consistent_snapshot":true,"keys":{},"roles":{}}}`)
	assert.NoError(t, json.Unmarshal(raw, root))

	out, err := root.MarshalJSON()
	assert.NoError(t, err)
	assert.Equal(t, original, expiresFromJSON(t, out),
		"re-marshaling parsed metadata must not rewrite expires, or signatures over it break")
}
