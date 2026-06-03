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

package fetcher

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

var sampleRootData = []byte{123, 10, 32, 34, 115, 105, 103, 110, 97, 116, 117, 114, 101, 115, 34, 58, 32, 91, 10, 32, 32, 123, 10, 32, 32, 32, 34, 107, 101, 121, 105, 100, 34, 58, 32, 34, 52, 99, 53, 54, 100, 101, 53, 98, 54, 50, 102, 100, 48, 54, 52, 102, 99, 57, 52, 52, 53, 51, 98, 54, 56, 48, 100, 102, 100, 51, 102, 97, 102, 54, 97, 48, 49, 98, 97, 97, 97, 98, 51, 98, 101, 97, 99, 50, 57, 54, 57, 50, 48, 102, 48, 99, 99, 102, 97, 50, 50, 55, 55, 53, 34, 44, 10, 32, 32, 32, 34, 115, 105, 103, 34, 58, 32, 34, 57, 54, 57, 98, 100, 101, 99, 51, 54, 100, 54, 102, 51, 100, 99, 53, 57, 99, 49, 55, 50, 48, 50, 97, 56, 53, 50, 56, 98, 98, 51, 53, 54, 97, 54, 101, 97, 53, 52, 100, 55, 99, 99, 57, 54, 98, 98, 51, 55, 49, 101, 101, 101, 52, 56, 101, 50, 52, 48, 49, 57, 50, 98, 99, 97, 99, 100, 53, 48, 53, 49, 51, 56, 56, 50, 52, 53, 49, 52, 52, 97, 97, 99, 97, 49, 48, 51, 57, 100, 51, 101, 98, 55, 48, 54, 50, 101, 48, 56, 55, 54, 55, 57, 53, 101, 56, 49, 101, 49, 100, 53, 54, 54, 102, 56, 100, 101, 100, 50, 99, 50, 56, 52, 97, 101, 101, 48, 102, 34, 10, 32, 32, 125, 44, 10, 32, 32, 123, 10, 32, 32, 32, 34, 107, 101, 121, 105, 100, 34, 58, 32, 34, 52, 53, 97, 57, 53, 55, 55, 99, 97, 52, 56, 51, 102, 51, 53, 56, 98, 100, 97, 52, 97, 50, 49, 97, 102, 57, 51, 98, 55, 54, 54, 48, 98, 56, 50, 98, 100, 57, 99, 48, 101, 49, 57, 51, 48, 97, 54, 98, 55, 100, 53, 50, 49, 98, 52, 50, 56, 57, 55, 97, 48, 102, 97, 51, 34, 44, 10, 32, 32, 32, 34, 115, 105, 103, 34, 58, 32, 34, 101, 100, 102, 97, 102, 51, 99, 53, 51, 56, 97, 48, 50, 51, 101, 55, 99, 102, 53, 98, 50, 54, 51, 97, 101, 52, 101, 54, 51, 99, 51, 51, 99, 57, 52, 97, 50, 98, 102, 99, 57, 102, 101, 56, 48, 56, 53, 57, 99, 52, 57, 51, 52, 100, 52, 97, 54, 54, 98, 48, 49, 53, 98, 54, 53, 98, 57, 48, 49, 101, 99, 53, 100, 53, 50, 57, 48, 101, 97, 53, 50, 52, 51, 51, 57, 101, 54, 97, 52, 48, 98, 53, 98, 56, 100, 98, 56, 97, 57, 53, 54, 49, 102, 51, 99, 49, 48, 51, 101, 50, 97, 101, 56, 55, 98, 57, 101, 101, 48, 51, 50, 97, 57, 101, 51, 48, 48, 49, 34, 10, 32, 32, 125, 10, 32, 93, 44, 10, 32, 34, 115, 105, 103, 110, 101, 100, 34, 58, 32, 123, 10, 32, 32, 34, 95, 116, 121, 112, 101, 34, 58, 32, 34, 114, 111, 111, 116, 34, 44, 10, 32, 32, 34, 99, 111, 110, 115, 105, 115, 116, 101, 110, 116, 95, 115, 110, 97, 112, 115, 104, 111, 116, 34, 58, 32, 116, 114, 117, 101, 44, 10, 32, 32, 34, 101, 120, 112, 105, 114, 101, 115, 34, 58, 32, 34, 50, 48, 50, 49, 45, 48, 55, 45, 49, 56, 84, 49, 51, 58, 51, 55, 58, 51, 56, 90, 34, 44, 10, 32, 32, 34, 107, 101, 121, 115, 34, 58, 32, 123, 10, 32, 32, 32, 34, 51, 56, 54, 48, 48, 56, 50, 48, 102, 49, 49, 97, 53, 102, 55, 100, 55, 102, 102, 52, 50, 101, 54, 100, 102, 99, 57, 98, 48, 51, 102, 100, 54, 48, 50, 55, 50, 97, 51, 98, 101, 54, 102, 56, 57, 53, 100, 97, 50, 100, 56, 56, 50, 99, 101, 97, 56, 98, 98, 49, 101, 50, 48, 102, 34, 58, 32, 123, 10, 32, 32, 32, 32, 34, 107, 101, 121, 105, 100, 34, 58, 32, 34, 51, 56, 54, 48, 48, 56, 50, 48, 102, 49, 49, 97, 53, 102, 55, 100, 55, 102, 102, 52, 50, 101, 54, 100, 102, 99, 57, 98, 48, 51, 102, 100, 54, 48, 50, 55, 50, 97, 51, 98, 101, 54, 102, 56, 57, 53, 100, 97, 50, 100, 56, 56, 50, 99, 101, 97, 56, 98, 98, 49, 101, 50, 48, 102, 34, 44, 10, 32, 32, 32, 32, 34, 107, 101, 121, 116, 121, 112, 101, 34, 58, 32, 34, 101, 100, 50, 53, 53, 49, 57, 34, 44, 10, 32, 32, 32, 32, 34, 107, 101, 121, 118, 97, 108, 34, 58, 32, 123, 10, 32, 32, 32, 32, 32, 34, 112, 117, 98, 108, 105, 99, 34, 58, 32, 34, 53, 48, 102, 52, 56, 54, 53, 57, 54, 54, 53, 98, 51, 101, 101, 98, 50, 50, 100, 52, 57, 51, 55, 52, 101, 49, 56, 51, 49, 57, 55, 101, 101, 102, 56, 101, 52, 50, 56, 55, 54, 97, 53, 99, 98, 57, 48, 57, 99, 57, 49, 97, 98, 55, 55, 101, 52, 50, 98, 49, 101, 99, 99, 54, 34, 10, 32, 32, 32, 32, 125, 44, 10, 32, 32, 32, 32, 34, 115, 99, 104, 101, 109, 101, 34, 58, 32, 34, 101, 100, 50, 53, 53, 49, 57, 34, 10, 32, 32, 32, 125, 44, 10, 32, 32, 32, 34, 52, 53, 97, 57, 53, 55, 55, 99, 97, 52, 56, 51, 102, 51, 53, 56, 98, 100, 97, 52, 97, 50, 49, 97, 102, 57, 51, 98, 55, 54, 54, 48, 98, 56, 50, 98, 100, 57, 99, 48, 101, 49, 57, 51, 48, 97, 54, 98, 55, 100, 53, 50, 49, 98, 52, 50, 56, 57, 55, 97, 48, 102, 97, 51, 34, 58, 32, 123, 10, 32, 32, 32, 32, 34, 107, 101, 121, 105, 100, 34, 58, 32, 34, 52, 53, 97, 57, 53, 55, 55, 99, 97, 52, 56, 51, 102, 51, 53, 56, 98, 100, 97, 52, 97, 50, 49, 97, 102, 57, 51, 98, 55, 54, 54, 48, 98, 56, 50, 98, 100, 57, 99, 48, 101, 49, 57, 51, 48, 97, 54, 98, 55, 100, 53, 50, 49, 98, 52, 50, 56, 57, 55, 97, 48, 102, 97, 51, 34, 44, 10, 32, 32, 32, 32, 34, 107, 101, 121, 116, 121, 112, 101, 34, 58, 32, 34, 101, 100, 50, 53, 53, 49, 57, 34, 44, 10, 32, 32, 32, 32, 34, 107, 101, 121, 118, 97, 108, 34, 58, 32, 123, 10, 32, 32, 32, 32, 32, 34, 112, 117, 98, 108, 105, 99, 34, 58, 32, 34, 49, 56, 101, 98, 50, 52, 56, 51, 49, 57, 54, 98, 55, 97, 97, 50, 53, 102, 97, 102, 98, 56, 49, 50, 55, 54, 99, 55, 48, 52, 102, 55, 57, 48, 51, 99, 99, 57, 98, 49, 101, 51, 52, 99, 97, 100, 99, 52, 101, 97, 102, 54, 55, 55, 98, 55, 97, 54, 55, 52, 100, 54, 102, 53, 34, 10, 32, 32, 32, 32, 125, 44, 10, 32, 32, 32, 32, 34, 115, 99, 104, 101, 109, 101, 34, 58, 32, 34, 101, 100, 50, 53, 53, 49, 57, 34, 10, 32, 32, 32, 125, 44, 10, 32, 32, 32, 34, 52, 99, 53, 54, 100, 101, 53, 98, 54, 50, 102, 100, 48, 54, 52, 102, 99, 57, 52, 52, 53, 51, 98, 54, 56, 48, 100, 102, 100, 51, 102, 97, 102, 54, 97, 48, 49, 98, 97, 97, 97, 98, 51, 98, 101, 97, 99, 50, 57, 54, 57, 50, 48, 102, 48, 99, 99, 102, 97, 50, 50, 55, 55, 53, 34, 58, 32, 123, 10, 32, 32, 32, 32, 34, 107, 101, 121, 105, 100, 34, 58, 32, 34, 52, 99, 53, 54, 100, 101, 53, 98, 54, 50, 102, 100, 48, 54, 52, 102, 99, 57, 52, 52, 53, 51, 98, 54, 56, 48, 100, 102, 100, 51, 102, 97, 102, 54, 97, 48, 49, 98, 97, 97, 97, 98, 51, 98, 101, 97, 99, 50, 57, 54, 57, 50, 48, 102, 48, 99, 99, 102, 97, 50, 50, 55, 55, 53, 34, 44, 10, 32, 32, 32, 32, 34, 107, 101, 121, 116, 121, 112, 101, 34, 58, 32, 34, 101, 100, 50, 53, 53, 49, 57, 34, 44, 10, 32, 32, 32, 32, 34, 107, 101, 121, 118, 97, 108, 34, 58, 32, 123, 10, 32, 32, 32, 32, 32, 34, 112, 117, 98, 108, 105, 99, 34, 58, 32, 34, 57, 50, 49, 101, 99, 99, 56, 54, 101, 101, 57, 49, 102, 100, 100, 51, 97, 53, 53, 49, 52, 48, 50, 51, 100, 102, 49, 57, 99, 100, 56, 53, 57, 49, 53, 57, 52, 54, 55, 55, 54, 52, 102, 54, 48, 102, 99, 52, 49, 101, 49, 101, 101, 97, 99, 56, 53, 48, 51, 53, 49, 49, 54, 49, 34, 10, 32, 32, 32, 32, 125, 44, 10, 32, 32, 32, 32, 34, 115, 99, 104, 101, 109, 101, 34, 58, 32, 34, 101, 100, 50, 53, 53, 49, 57, 34, 10, 32, 32, 32, 125, 44, 10, 32, 32, 32, 34, 56, 102, 51, 99, 50, 55, 57, 52, 102, 50, 52, 52, 50, 54, 48, 49, 52, 102, 99, 50, 54, 97, 100, 99, 98, 98, 56, 101, 102, 100, 57, 52, 52, 49, 49, 102, 99, 101, 56, 56, 49, 102, 97, 54, 48, 102, 99, 56, 55, 50, 53, 97, 56, 57, 57, 49, 49, 53, 55, 53, 48, 101, 102, 97, 34, 58, 32, 123, 10, 32, 32, 32, 32, 34, 107, 101, 121, 105, 100, 34, 58, 32, 34, 56, 102, 51, 99, 50, 55, 57, 52, 102, 50, 52, 52, 50, 54, 48, 49, 52, 102, 99, 50, 54, 97, 100, 99, 98, 98, 56, 101, 102, 100, 57, 52, 52, 49, 49, 102, 99, 101, 56, 56, 49, 102, 97, 54, 48, 102, 99, 56, 55, 50, 53, 97, 56, 57, 57, 49, 49, 53, 55, 53, 48, 101, 102, 97, 34, 44, 10, 32, 32, 32, 32, 34, 107, 101, 121, 116, 121, 112, 101, 34, 58, 32, 34, 101, 100, 50, 53, 53, 49, 57, 34, 44, 10, 32, 32, 32, 32, 34, 107, 101, 121, 118, 97, 108, 34, 58, 32, 123, 10, 32, 32, 32, 32, 32, 34, 112, 117, 98, 108, 105, 99, 34, 58, 32, 34, 56, 57, 53, 55, 54, 57, 49, 55, 100, 49, 54, 48, 50, 56, 52, 51, 56, 52, 97, 52, 55, 55, 53, 57, 101, 101, 99, 49, 102, 99, 48, 102, 53, 98, 55, 52, 54, 99, 97, 51, 100, 102, 97, 100, 56, 49, 51, 101, 101, 51, 48, 56, 55, 53, 99, 51, 50, 98, 97, 99, 51, 54, 57, 99, 34, 10, 32, 32, 32, 32, 125, 44, 10, 32, 32, 32, 32, 34, 115, 99, 104, 101, 109, 101, 34, 58, 32, 34, 101, 100, 50, 53, 53, 49, 57, 34, 10, 32, 32, 32, 125, 44, 10, 32, 32, 32, 34, 57, 100, 55, 56, 53, 52, 51, 98, 53, 48, 56, 102, 57, 57, 97, 57, 53, 97, 51, 99, 51, 49, 102, 97, 100, 51, 99, 102, 102, 101, 102, 48, 54, 52, 52, 49, 51, 52, 102, 49, 97, 48, 50, 56, 98, 51, 48, 53, 48, 49, 97, 99, 99, 49, 50, 48, 53, 56, 99, 55, 99, 51, 101, 56, 34, 58, 32, 123, 10, 32, 32, 32, 32, 34, 107, 101, 121, 105, 100, 34, 58, 32, 34, 57, 100, 55, 56, 53, 52, 51, 98, 53, 48, 56, 102, 57, 57, 97, 57, 53, 97, 51, 99, 51, 49, 102, 97, 100, 51, 99, 102, 102, 101, 102, 48, 54, 52, 52, 49, 51, 52, 102, 49, 97, 48, 50, 56, 98, 51, 48, 53, 48, 49, 97, 99, 99, 49, 50, 48, 53, 56, 99, 55, 99, 51, 101, 56, 34, 44, 10, 32, 32, 32, 32, 34, 107, 101, 121, 116, 121, 112, 101, 34, 58, 32, 34, 101, 100, 50, 53, 53, 49, 57, 34, 44, 10, 32, 32, 32, 32, 34, 107, 101, 121, 118, 97, 108, 34, 58, 32, 123, 10, 32, 32, 32, 32, 32, 34, 112, 117, 98, 108, 105, 99, 34, 58, 32, 34, 48, 52, 101, 102, 51, 51, 53, 54, 102, 98, 53, 99, 100, 48, 48, 57, 55, 53, 100, 102, 99, 101, 57, 102, 56, 102, 52, 50, 100, 53, 98, 49, 50, 98, 55, 98, 56, 51, 102, 56, 98, 97, 49, 53, 99, 50, 101, 57, 56, 102, 100, 48, 52, 49, 53, 49, 52, 99, 55, 52, 98, 101, 98, 50, 34, 10, 32, 32, 32, 32, 125, 44, 10, 32, 32, 32, 32, 34, 115, 99, 104, 101, 109, 101, 34, 58, 32, 34, 101, 100, 50, 53, 53, 49, 57, 34, 10, 32, 32, 32, 125, 10, 32, 32, 125, 44, 10, 32, 32, 34, 114, 111, 108, 101, 115, 34, 58, 32, 123, 10, 32, 32, 32, 34, 114, 111, 111, 116, 34, 58, 32, 123, 10, 32, 32, 32, 32, 34, 107, 101, 121, 105, 100, 115, 34, 58, 32, 91, 10, 32, 32, 32, 32, 32, 34, 52, 53, 97, 57, 53, 55, 55, 99, 97, 52, 56, 51, 102, 51, 53, 56, 98, 100, 97, 52, 97, 50, 49, 97, 102, 57, 51, 98, 55, 54, 54, 48, 98, 56, 50, 98, 100, 57, 99, 48, 101, 49, 57, 51, 48, 97, 54, 98, 55, 100, 53, 50, 49, 98, 52, 50, 56, 57, 55, 97, 48, 102, 97, 51, 34, 44, 10, 32, 32, 32, 32, 32, 34, 52, 99, 53, 54, 100, 101, 53, 98, 54, 50, 102, 100, 48, 54, 52, 102, 99, 57, 52, 52, 53, 51, 98, 54, 56, 48, 100, 102, 100, 51, 102, 97, 102, 54, 97, 48, 49, 98, 97, 97, 97, 98, 51, 98, 101, 97, 99, 50, 57, 54, 57, 50, 48, 102, 48, 99, 99, 102, 97, 50, 50, 55, 55, 53, 34, 10, 32, 32, 32, 32, 93, 44, 10, 32, 32, 32, 32, 34, 116, 104, 114, 101, 115, 104, 111, 108, 100, 34, 58, 32, 50, 10, 32, 32, 32, 125, 44, 10, 32, 32, 32, 34, 115, 110, 97, 112, 115, 104, 111, 116, 34, 58, 32, 123, 10, 32, 32, 32, 32, 34, 107, 101, 121, 105, 100, 115, 34, 58, 32, 91, 10, 32, 32, 32, 32, 32, 34, 57, 100, 55, 56, 53, 52, 51, 98, 53, 48, 56, 102, 57, 57, 97, 57, 53, 97, 51, 99, 51, 49, 102, 97, 100, 51, 99, 102, 102, 101, 102, 48, 54, 52, 52, 49, 51, 52, 102, 49, 97, 48, 50, 56, 98, 51, 48, 53, 48, 49, 97, 99, 99, 49, 50, 48, 53, 56, 99, 55, 99, 51, 101, 56, 34, 10, 32, 32, 32, 32, 93, 44, 10, 32, 32, 32, 32, 34, 116, 104, 114, 101, 115, 104, 111, 108, 100, 34, 58, 32, 49, 10, 32, 32, 32, 125, 44, 10, 32, 32, 32, 34, 116, 97, 114, 103, 101, 116, 115, 34, 58, 32, 123, 10, 32, 32, 32, 32, 34, 107, 101, 121, 105, 100, 115, 34, 58, 32, 91, 10, 32, 32, 32, 32, 32, 34, 56, 102, 51, 99, 50, 55, 57, 52, 102, 50, 52, 52, 50, 54, 48, 49, 52, 102, 99, 50, 54, 97, 100, 99, 98, 98, 56, 101, 102, 100, 57, 52, 52, 49, 49, 102, 99, 101, 56, 56, 49, 102, 97, 54, 48, 102, 99, 56, 55, 50, 53, 97, 56, 57, 57, 49, 49, 53, 55, 53, 48, 101, 102, 97, 34, 10, 32, 32, 32, 32, 93, 44, 10, 32, 32, 32, 32, 34, 116, 104, 114, 101, 115, 104, 111, 108, 100, 34, 58, 32, 49, 10, 32, 32, 32, 125, 44, 10, 32, 32, 32, 34, 116, 105, 109, 101, 115, 116, 97, 109, 112, 34, 58, 32, 123, 10, 32, 32, 32, 32, 34, 107, 101, 121, 105, 100, 115, 34, 58, 32, 91, 10, 32, 32, 32, 32, 32, 34, 51, 56, 54, 48, 48, 56, 50, 48, 102, 49, 49, 97, 53, 102, 55, 100, 55, 102, 102, 52, 50, 101, 54, 100, 102, 99, 57, 98, 48, 51, 102, 100, 54, 48, 50, 55, 50, 97, 51, 98, 101, 54, 102, 56, 57, 53, 100, 97, 50, 100, 56, 56, 50, 99, 101, 97, 56, 98, 98, 49, 101, 50, 48, 102, 34, 10, 32, 32, 32, 32, 93, 44, 10, 32, 32, 32, 32, 34, 116, 104, 114, 101, 115, 104, 111, 108, 100, 34, 58, 32, 49, 10, 32, 32, 32, 125, 10, 32, 32, 125, 44, 10, 32, 32, 34, 115, 112, 101, 99, 95, 118, 101, 114, 115, 105, 111, 110, 34, 58, 32, 34, 49, 46, 48, 46, 49, 57, 34, 44, 10, 32, 32, 34, 118, 101, 114, 115, 105, 111, 110, 34, 58, 32, 49, 44, 10, 32, 32, 34, 120, 45, 116, 117, 102, 114, 101, 112, 111, 45, 101, 120, 112, 105, 114, 121, 45, 112, 101, 114, 105, 111, 100, 34, 58, 32, 56, 54, 52, 48, 48, 10, 32, 125, 10, 125}

// newRootServer returns an httptest.Server that serves sampleRootData on
// "/1.root.json" with a correct Content-Length, and 404s on every other
// path. The returned server is registered with t.Cleanup so callers don't
// have to remember to close it.
func newRootServer(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/1.root.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(sampleRootData)))
		_, _ = w.Write(sampleRootData)
	}))
	t.Cleanup(s.Close)
	return s
}

// TestDownLoadFile drives DownloadFile against a local httptest.Server
// (no external network), covering the success path, an unreachable host,
// a malformed URL, a 404 response, and length-cap enforcement.
func TestDownLoadFile(t *testing.T) {
	tests := []struct {
		name      string
		desc      string
		makeURL   func(server *httptest.Server) string
		maxLength int64
		data      []byte
		wantErr   error
	}{
		{
			name:      "success",
			desc:      "No errors expected",
			makeURL:   func(s *httptest.Server) string { return s.URL + "/1.root.json" },
			maxLength: 512000,
			data:      sampleRootData,
			wantErr:   nil,
		},
		{
			name:    "invalid url",
			desc:    "URL does not resolve",
			makeURL: func(*httptest.Server) string { return "http://127.0.0.1:1/" },
			data:    nil,
			wantErr: &url.Error{},
		},
		{
			name:    "invalid url format",
			desc:    "URL is malformed",
			makeURL: func(*httptest.Server) string { return string([]byte{0x7f}) },
			data:    nil,
			wantErr: &url.Error{},
		},
		{
			name:    "invalid path",
			desc:    "Server returns 404",
			makeURL: func(s *httptest.Server) string { return s.URL + "/badPath.json" },
			data:    nil,
			wantErr: &metadata.ErrDownloadHTTP{},
		},
		{
			name:      "data too long",
			desc:      "Returned data exceeds maxLength",
			makeURL:   func(s *httptest.Server) string { return s.URL + "/1.root.json" },
			maxLength: 1,
			data:      nil,
			wantErr:   &metadata.ErrDownloadLengthMismatch{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Desc: %s", tt.desc)
			server := newRootServer(t)
			fetcher := NewDefaultFetcher()
			fetcher.SetHTTPUserAgent("Metadata_Unit_Test/1.0")
			data, err := fetcher.DownloadFile(tt.makeURL(server), tt.maxLength, 0)
			if tt.wantErr == nil {
				assert.NoErrorf(t, err, "expected no error but got %v", err)
				return
			}
			assert.Equal(t, tt.data, data, "fetched data did not match")
			assert.IsTypef(t, tt.wantErr, err, "expected %v but got %v", tt.wantErr, err)
		})
	}
}

// TestDownLoadFile_BodyExceedsLimit covers the post-read LimitReader check
// in DownloadFile: a server that omits Content-Length but returns a body
// larger than maxLength must trip ErrDownloadLengthMismatch.
func TestDownLoadFile_BodyExceedsLimit(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No Content-Length so the in-flight check is skipped; rely on
		// the LimitReader path that fires after io.ReadAll returns.
		w.Header().Del("Content-Length")
		_, _ = io.Copy(w, strings.NewReader(strings.Repeat("x", 200)))
	}))
	t.Cleanup(s.Close)

	f := NewDefaultFetcher()
	_, err := f.DownloadFile(s.URL, 10, 0)
	assert.ErrorAs(t, err, new(*metadata.ErrDownloadLengthMismatch))
}

// MockHTTPClient is a mock implementation of httpClient
// for simulating HTTP requests in tests
type MockHTTPClient struct {
	TryCount      int
	SucceedOnTryN int
	AlwaysFail    bool
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.TryCount++
	if m.AlwaysFail || (m.TryCount < m.SucceedOnTryN) {
		return nil, fmt.Errorf("request failed")
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(sampleRootData)),
	}, nil
}

func TestDownloadFile_Retry(t *testing.T) {
	for _, tt := range []struct {
		name          string
		shouldSucceed bool
		succeedOnTryN int
		httpClient    *MockHTTPClient
	}{
		{
			name:          "retry succeeds on try 3",
			shouldSucceed: true,
			succeedOnTryN: 3,
			httpClient: &MockHTTPClient{
				SucceedOnTryN: 3,
			},
		},
		{
			name:          "retry always fails",
			shouldSucceed: false,
			httpClient: &MockHTTPClient{
				AlwaysFail: true,
			},
		},
		{
			name:          "request succeeds on try 1",
			shouldSucceed: true,
			succeedOnTryN: 1,
			httpClient: &MockHTTPClient{
				SucceedOnTryN: 1,
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.httpClient
			fetcher := &DefaultFetcher{
				client: client,
				retryOptions: []backoff.RetryOption{
					backoff.WithMaxTries(3),
				},
			}
			data, err := fetcher.DownloadFile("https://jku.github.io/tuf-demo/metadata/1.root.json", 512000, 0)
			if tt.shouldSucceed {
				assert.Equal(t, sampleRootData, data)
				assert.NoError(t, err)
				assert.Equal(t, tt.succeedOnTryN, client.TryCount, "expected %d try but got %d", tt.succeedOnTryN, client.TryCount)
				return
			} else {
				assert.Nil(t, data)
				assert.Error(t, err)
				assert.Equal(t, 3, client.TryCount, "expected 3 try but got %d", client.TryCount)
			}
		})
	}
}

// TestDownloadFile_NoHTTPClientSet covers the "if d.client == nil, fall
// back to http.DefaultClient" branch in DownloadFile.
func TestDownloadFile_NoHTTPClientSet(t *testing.T) {
	server := newRootServer(t)
	fetcher := DefaultFetcher{}
	_, err := fetcher.DownloadFile(server.URL+"/1.root.json", 512000, 0)
	assert.NoError(t, err)
}

// TestNewFetcherWithHTTPClient verifies that the constructor returns a
// fetcher whose internal client is the one we passed in.
func TestNewFetcherWithHTTPClient(t *testing.T) {
	base := &DefaultFetcher{}
	custom := &MockHTTPClient{SucceedOnTryN: 1}
	got := base.NewFetcherWithHTTPClient(custom)
	assert.NotNil(t, got)
	assert.Same(t, custom, got.client)
}

// TestNewFetcherWithRoundTripper verifies that the returned fetcher has the
// supplied RoundTripper installed on its http.Client. The constructor mutates
// http.DefaultClient -- that's an upstream wart, but we want to know if the
// returned fetcher is at least usable.
func TestNewFetcherWithRoundTripper(t *testing.T) {
	base := &DefaultFetcher{}
	rt := http.DefaultTransport
	got := base.NewFetcherWithRoundTripper(rt)
	assert.NotNil(t, got)
	hc, ok := got.client.(*http.Client)
	if assert.True(t, ok, "client must be *http.Client") {
		assert.Same(t, rt, hc.Transport)
	}
}

// TestSetHTTPClient verifies the setter swaps the underlying client.
func TestSetHTTPClient(t *testing.T) {
	f := NewDefaultFetcher()
	custom := &MockHTTPClient{SucceedOnTryN: 1}
	f.SetHTTPClient(custom)
	assert.Same(t, custom, f.client)
}

// TestSetTransportTable covers both branches of SetTransport: the happy
// path on a *http.Client, and the failure path when the underlying client
// is something else (e.g. a test mock).
func TestSetTransportTable(t *testing.T) {
	tests := []struct {
		name        string
		setup       func() *DefaultFetcher
		expectError bool
		errorMsg    string
	}{
		{
			name: "fetcher backed by *http.Client accepts a new transport",
			setup: func() *DefaultFetcher {
				return NewDefaultFetcher() // internal client is *http.Client
			},
		},
		{
			name: "fetcher backed by a mock client rejects SetTransport",
			setup: func() *DefaultFetcher {
				f := NewDefaultFetcher()
				f.SetHTTPClient(&MockHTTPClient{SucceedOnTryN: 1})
				return f
			},
			expectError: true,
			errorMsg:    "fetcher is not type fetcher.DefaultFetcher",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.setup()
			rt := http.DefaultTransport
			err := f.SetTransport(rt)
			if tt.expectError {
				assert.ErrorContains(t, err, tt.errorMsg)
				return
			}
			assert.NoError(t, err)
			hc, ok := f.client.(*http.Client)
			if assert.True(t, ok) {
				assert.Same(t, rt, hc.Transport)
			}
		})
	}
}

// TestSetRetry verifies that SetRetry installs constant-interval retry
// options on the fetcher.
func TestSetRetry(t *testing.T) {
	tests := []struct {
		name     string
		interval time.Duration
		count    uint
	}{
		{name: "non-zero interval and count", interval: 100 * time.Millisecond, count: 3},
		{name: "zero interval and count", interval: 0, count: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewDefaultFetcher()
			f.SetRetry(tt.interval, tt.count)
			// SetRetry replaces retryOptions with [constantBackOff, maxTries].
			assert.Len(t, f.retryOptions, 2)
		})
	}
}

// TestSetRetryOptions verifies that SetRetryOptions replaces the entire
// retryOptions slice with whatever the caller passes.
func TestSetRetryOptions(t *testing.T) {
	tests := []struct {
		name     string
		opts     []backoff.RetryOption
		expected int
	}{
		{name: "nil clears retry options", opts: nil, expected: 0},
		{name: "one option installs one", opts: []backoff.RetryOption{backoff.WithMaxTries(5)}, expected: 1},
		{
			name: "multiple options install all of them",
			opts: []backoff.RetryOption{
				backoff.WithMaxTries(5),
				backoff.WithBackOff(backoff.NewConstantBackOff(0)),
			},
			expected: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewDefaultFetcher()
			f.SetRetryOptions(tt.opts...)
			assert.Len(t, f.retryOptions, tt.expected)
		})
	}
}
