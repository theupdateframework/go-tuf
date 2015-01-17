package client

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

func HTTPRemoteStore(baseURL string) (RemoteStore, error) {
	if !strings.HasPrefix(baseURL, "http") {
		return nil, ErrInvalidURL{baseURL}
	}
	return &httpRemoteStore{baseURL}, nil
}

type httpRemoteStore struct {
	baseURL string
}

func (h *httpRemoteStore) Get(path string) (io.ReadCloser, int64, error) {
	res, err := http.Get(h.url(path))
	if err != nil {
		return nil, 0, err
	}

	if res.StatusCode == http.StatusNotFound {
		res.Body.Close()
		return nil, 0, ErrNotFound{path}
	} else if res.StatusCode != http.StatusOK {
		res.Body.Close()
		return nil, 0, fmt.Errorf("unexpected HTTP response code: %d", res.StatusCode)
	}

	size, err := strconv.ParseInt(res.Header.Get("Content-Length"), 10, 0)
	if err != nil {
		return res.Body, -1, nil
	}
	return res.Body, size, nil
}

func (h *httpRemoteStore) url(path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return h.baseURL + path
}
