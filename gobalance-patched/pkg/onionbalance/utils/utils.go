package utils

import (
	"errors"
	"os"
)

func Ternary[T any](predicate bool, a, b T) T {
	if predicate {
		return a
	}
	return b
}

func FileExists(filePath string) bool {
	if _, err := os.Stat(filePath); errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}

// Noop takes a value and return it directly
// This is useful to remove warnings in an IDE
func Noop[T any](v T) T {
	return v
}

// BConcat concatenate multiple byte arrays into a single one.
func BConcat(vals ...[]byte) []byte {
	var l int
	for _, val := range vals {
		l += len(val)
	}
	offset := 0
	out := make([]byte, l)
	for _, val := range vals {
		copy(out[offset:], val)
		offset += len(val)
	}
	return out
}

func InArr[T comparable](needle T, haystack []T) bool {
	for _, el := range haystack {
		if el == needle {
			return true
		}
	}
	return false
}
