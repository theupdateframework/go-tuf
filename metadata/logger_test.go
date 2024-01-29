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
	stdlog "log"
	"os"
	"testing"

	"github.com/go-logr/stdr"
	"github.com/stretchr/testify/assert"
)

func TestSetLogger(t *testing.T) {
	// This function is just a simple setter, no need for testing table
	testLogger := stdr.New(stdlog.New(os.Stdout, "test", stdlog.LstdFlags))
	SetLogger(testLogger)
	assert.Equal(t, testLogger, log, "setting package global logger was unsuccessful")
}

func TestGetLogger(t *testing.T) {
	// This function is just a simple getter, no need for testing table
	testLogger := GetLogger()
	assert.Equal(t, log, testLogger, "function did not return current logger")
}
