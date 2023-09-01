// Copyright 2023 VMware, Inc.
//
// This product is licensed to you under the BSD-2 license (the "License").
// You may not use this product except in compliance with the BSD-2 License.
// This product may include a number of subcomponents with separate copyright
// notices and license terms. Your use of these subcomponents is subject to
// the terms and conditions of the subcomponent's license, as noted in the
// LICENSE file.
//
// SPDX-License-Identifier: BSD-2-Clause

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
