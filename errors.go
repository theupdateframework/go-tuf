package tuf

import "fmt"

type ErrMissingMetadata struct {
	Name string
}

func (e ErrMissingMetadata) Error() string {
	return fmt.Sprintf("tuf: missing metadata %s", e.Name)
}

type ErrFileNotFound struct {
	path string
}

func (e ErrFileNotFound) Error() string {
	return fmt.Sprintf("tuf: file not found %s", e.path)
}

type ErrInsufficientKeys struct {
	Name string
}

func (e ErrInsufficientKeys) Error() string {
	return fmt.Sprintf("tuf: insufficient keys to sign %s", e.Name)
}

type ErrInsufficientSignatures struct {
	Name string
	Err  error
}

func (e ErrInsufficientSignatures) Error() string {
	return fmt.Sprintf("tuf: insufficient signatures for %s: %s", e.Name, e.Err)
}
