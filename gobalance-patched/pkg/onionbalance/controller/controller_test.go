package controller

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestConnScannerThread(t *testing.T) {
	r := strings.NewReader(`650+HS_DESC_CONTENT line1
line2
line3
650 OK
650 HS_DESC line1
250 OK`)
	var msg1, msg2, msg3 TorReply
	var msgCount int
	clb := func(msg TorReply) {
		msgCount++
		if msgCount == 1 {
			msg1 = msg
		} else if msgCount == 2 {
			msg2 = msg
		} else if msgCount == 3 {
			msg3 = msg
		}
	}
	connScannerThread(r, clb)
	assert.Equal(t, 3, msgCount)
	assert.Equal(t, "650", msg1.code)
	assert.Equal(t, "HS_DESC_CONTENT line1\nline2\nline3", msg1.inner)
	assert.Equal(t, "650", msg2.code)
	assert.Equal(t, "HS_DESC line1", msg2.inner)
	assert.Equal(t, "250", msg3.code)
	assert.Equal(t, "OK", msg3.inner)
}
