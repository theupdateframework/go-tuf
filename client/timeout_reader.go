package client

import (
	"errors"
	"io"
	"time"
)

var ErrTimeout = errors.New("timeout")

// timeoutReader wraps an io.Reader and times out if the read rate is lower
// than chunkSize per second
// TODO: use gracePeriod
type timeoutReader struct {
	r           io.Reader
	gracePeriod time.Duration
	chunkSize   int
}

const (
	defaultGracePeriod = 4 * time.Second
	defaultChunkSize   = 8 * 1024
)

// newTimeoutReader returns a timeoutReader with default gracePeriod and chunkSize
func newTimeoutReader(r io.Reader) *timeoutReader {
	return &timeoutReader{r, defaultGracePeriod, defaultChunkSize}
}

// readResult represents the return value of a read
type readResult struct {
	n   int
	err error
}

// Read reads from t.r, timing out if the read rate is lower than t.chunkSize per second
func (t *timeoutReader) Read(p []byte) (int, error) {
	if len(p) < t.chunkSize {
		timeout := (time.Duration(len(p)) * time.Second) / time.Duration(t.chunkSize)
		return t.readWithTimeout(p, timeout)
	}
	var pos int
	for {
		size := t.chunkSize
		if size > len(p)-pos {
			size = len(p) - pos
		}
		m, err := t.readWithTimeout(p[pos:size], time.Second)
		pos += m
		if pos == len(p) || err != nil {
			return pos, err
		}
	}
}

func (t *timeoutReader) readWithTimeout(p []byte, timeout time.Duration) (int, error) {
	done := make(chan *readResult)
	go func() {
		res := &readResult{}
		res.n, res.err = t.r.Read(p)
		done <- res
	}()
	select {
	case res := <-done:
		return res.n, res.err
	case <-time.After(timeout):
		return 0, ErrTimeout
	}
}
