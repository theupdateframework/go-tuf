package tuf

import (
	"fmt"
	"time"
)

type ErrMissingMetadata struct {
	Name string
}

func (e ErrMissingMetadata) Error() string {
	return fmt.Sprintf("tuf: missing metadata %s", e.Name)
}

type ErrFileNotFound struct {
	Path string
}

func (e ErrFileNotFound) Error() string {
	return fmt.Sprintf("tuf: file not found %s", e.Path)
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

type ErrInvalidRole struct {
	Role string
}

func (e ErrInvalidRole) Error() string {
	return fmt.Sprintf("tuf: invalid role %s", e.Role)
}

type ErrInvalidExpires struct {
	Expires time.Time
}

func (e ErrInvalidExpires) Error() string {
	return fmt.Sprintf("tuf: invalid expires: %s", e.Expires)
}
