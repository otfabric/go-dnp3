// SPDX-License-Identifier: MIT

package app

import (
	"errors"
	"fmt"
)

// Errors returned by [Decode] and the encoders. They are wrapped with
// detail; test with errors.Is.
//
// An outstation answers a request that fails with [ErrUnknownObject] with
// IIN2.1 (OBJECT_UNKNOWN) and one that fails with [ErrMalformed] or
// [ErrInvalidQualifier] with IIN2.2 (PARAMETER_ERROR).
var (
	// ErrMalformed reports a fragment that cannot be parsed: too short,
	// a count or range that does not fit the remaining octets, or a field
	// with a value the object does not allow.
	ErrMalformed = errors.New("app: malformed fragment")

	// ErrUnknownObject reports a group and variation this package does not
	// know, in a position where its size must be known to continue.
	ErrUnknownObject = errors.New("app: unknown object")

	// ErrInvalidQualifier reports a qualifier code that is reserved or not
	// allowed for the object.
	ErrInvalidQualifier = errors.New("app: invalid qualifier")

	// ErrInvalidValue reports a header or object that cannot be encoded:
	// a value of the wrong type for the variation, indexes that do not fit
	// the qualifier, or a field that is too long.
	ErrInvalidValue = errors.New("app: invalid value")
)

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrMalformed}, args...)...)
}

func truncated(format string, args ...any) error {
	return fmt.Errorf("%w: truncated "+format, append([]any{ErrMalformed}, args...)...)
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidValue}, args...)...)
}
