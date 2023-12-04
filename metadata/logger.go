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

var log Logger = DiscardLogger{}

// Logger partially implements the go-log/logr's interface:
// https://github.com/go-logr/logr/blob/master/logr.go
type Logger interface {
	// Info logs a non-error message with key/value pairs
	Info(msg string, kv ...any)
	// Error logs an error with a given message and key/value pairs.
	Error(err error, msg string, kv ...any)
}

type DiscardLogger struct{}

func (d DiscardLogger) Info(msg string, kv ...any) {
}

func (d DiscardLogger) Error(err error, msg string, kv ...any) {
}

func SetLogger(logger Logger) {
	log = logger
}

func GetLogger() Logger {
	return log
}
