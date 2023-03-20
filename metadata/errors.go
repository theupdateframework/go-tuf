package metadata

import (
	"fmt"
)

// Define TUF error types used inside the new modern implementation.
// The names chosen for TUF error types should start in 'Err' except where
// there is a good reason not to, and provide that reason in those cases.

// Repository errors

// ErrRepository - an error with a repository's state, such as a missing file.
// It covers all exceptions that come from the repository side when
// looking from the perspective of users of metadata API or client
type ErrRepository struct {
	Msg string
}

func (e ErrRepository) Error() string {
	return fmt.Sprintf("repository error: %s", e.Msg)
}

// ErrUnsignedMetadata - An error about metadata object with insufficient threshold of signatures
type ErrUnsignedMetadata struct {
	Msg string
}

func (e ErrUnsignedMetadata) Error() string {
	return fmt.Sprintf("unsigned metadata error: %s", e.Msg)
}

// ErrUnsignedMetadata is a subset of ErrRepository
func (e ErrUnsignedMetadata) Is(target error) bool {
	return target == ErrRepository{} || target == ErrUnsignedMetadata{}
}

// ErrBadVersionNumber - An error for metadata that contains an invalid version number
type ErrBadVersionNumber struct {
	Msg string
}

func (e ErrBadVersionNumber) Error() string {
	return fmt.Sprintf("bad version number error: %s", e.Msg)
}

// ErrBadVersionNumber is a subset of ErrRepository
func (e ErrBadVersionNumber) Is(target error) bool {
	return target == ErrRepository{} || target == ErrBadVersionNumber{}
}

// ErrEqualVersionNumber - An error for metadata containing a previously verified version number
type ErrEqualVersionNumber struct {
	Msg string
}

func (e ErrEqualVersionNumber) Error() string {
	return fmt.Sprintf("equal version number error: %s", e.Msg)
}

// ErrEqualVersionNumber is a subset of both ErrRepository and ErrBadVersionNumber
func (e ErrEqualVersionNumber) Is(target error) bool {
	return target == ErrRepository{} || target == ErrBadVersionNumber{} || target == ErrEqualVersionNumber{}
}

// ErrExpiredMetadata - Indicate that a TUF Metadata file has expired
type ErrExpiredMetadata struct {
	Msg string
}

func (e ErrExpiredMetadata) Error() string {
	return fmt.Sprintf("expired metadata error: %s", e.Msg)
}

// ErrExpiredMetadata is a subset of ErrRepository
func (e ErrExpiredMetadata) Is(target error) bool {
	return target == ErrRepository{} || target == ErrExpiredMetadata{}
}

// ErrLengthOrHashMismatch - An error while checking the length and hash values of an object
type ErrLengthOrHashMismatch struct {
	Msg string
}

func (e ErrLengthOrHashMismatch) Error() string {
	return fmt.Sprintf("length/hash verification error: %s", e.Msg)
}

// ErrLengthOrHashMismatch is a subset of ErrRepository
func (e ErrLengthOrHashMismatch) Is(target error) bool {
	return target == ErrRepository{} || target == ErrLengthOrHashMismatch{}
}

// Download errors

// ErrDownload - An error occurred while attempting to download a file
type ErrDownload struct {
	Msg string
}

func (e ErrDownload) Error() string {
	return fmt.Sprintf("download error: %s", e.Msg)
}

// ErrDownloadLengthMismatch - Indicate that a mismatch of lengths was seen while downloading a file
type ErrDownloadLengthMismatch struct {
	Msg string
}

func (e ErrDownloadLengthMismatch) Error() string {
	return fmt.Sprintf("download length mismatch error: %s", e.Msg)
}

// ErrDownloadLengthMismatch is a subset of ErrDownload
func (e ErrDownloadLengthMismatch) Is(target error) bool {
	return target == ErrDownload{} || target == ErrDownloadLengthMismatch{}
}

// ErrDownloadHTTP - Returned by Fetcher interface implementations for HTTP errors
type ErrDownloadHTTP struct {
	StatusCode int
	URL        string
}

func (e ErrDownloadHTTP) Error() string {
	return fmt.Sprintf("failed to download %s, http status code: %d", e.URL, e.StatusCode)
}

// ErrDownloadHTTP is a subset of ErrDownload
func (e ErrDownloadHTTP) Is(target error) bool {
	return target == ErrDownload{} || target == ErrDownloadHTTP{}
}

// ValueError
type ErrValue struct {
	Msg string
}

func (e ErrValue) Error() string {
	return fmt.Sprintf("value error: %s", e.Msg)
}

// TypeError
type ErrType struct {
	Msg string
}

func (e ErrType) Error() string {
	return fmt.Sprintf("type error: %s", e.Msg)
}

// RuntimeError
type ErrRuntime struct {
	Msg string
}

func (e ErrRuntime) Error() string {
	return fmt.Sprintf("runtime error: %s", e.Msg)
}
