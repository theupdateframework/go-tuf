package fetcher

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
)

// Fetcher interface
type Fetcher interface {
	DownloadFile(urlPath string, maxLength int64) ([]byte, error)
}

// Default fetcher
type DefaultFetcher struct {
	httpUserAgent string
}

// DownloadFile downloads a file from urlPath, errors out if it failed or its length is larger than maxLength
func (d *DefaultFetcher) DownloadFile(urlPath string, maxLength int64) ([]byte, error) {
	client := http.DefaultClient
	req, err := http.NewRequest("GET", urlPath, nil)
	if err != nil {
		return nil, err
	}
	// use in case of multiple sessions
	if d.httpUserAgent != "" {
		req.Header.Set("User-Agent", d.httpUserAgent)
	}
	// execute the request
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	// handle HTTP status codes
	if res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusForbidden || res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download %s, http status code: %d", urlPath, res.StatusCode)
	}
	// get content length
	length, err := strconv.ParseInt(res.Header.Get("Content-Length"), 10, 0)
	if err != nil {
		return nil, err
	}
	// error if the reported size is greater than what is expected
	if length > maxLength {
		return nil, fmt.Errorf("download failed for %s, length %d is larger than expected %d", urlPath, length, maxLength)
	}
	// although the size has been checked above, use a LimitReader in case
	// the reported size is inaccurate, or size is -1 which indicates an
	// unknown length
	return io.ReadAll(io.LimitReader(res.Body, maxLength))
}
