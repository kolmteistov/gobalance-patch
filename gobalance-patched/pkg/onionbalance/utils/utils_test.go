package utils

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBConcat(t *testing.T) {
	assert.Equal(t, []byte("Hello world!"), BConcat([]byte("Hello"), []byte(" world"), []byte("!")))
}
