package client

import (
	"io"
	"net/url"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

// S3RemoteOptions TODO doc
type S3RemoteOptions struct {
	MetadataPath string
	TargetsPath  string
}

// S3RemoteStore TODO doc
func S3RemoteStore(baseURL string, opts *S3RemoteOptions) (RemoteStore, error) {
	if !strings.HasPrefix(baseURL, "s3") {
		return nil, ErrInvalidURL{baseURL}
	}
	if opts == nil {
		opts = &S3RemoteOptions{}
	}
	if opts.TargetsPath == "" {
		opts.TargetsPath = "targets"
	}

	session := session.New(&aws.Config{Region: aws.String("us-west-2")})
	return &s3RemoteStore{baseURL, opts, session}, nil
}

type s3RemoteStore struct {
	baseURL string
	opts    *S3RemoteOptions
	session *session.Session
}

func (h *s3RemoteStore) GetMeta(name string) (io.ReadCloser, int64, error) {
	return h.get(path.Join(h.opts.MetadataPath, name))
}

func (h *s3RemoteStore) GetTarget(name string) (io.ReadCloser, int64, error) {
	return h.get(path.Join(h.opts.TargetsPath, name))
}

func (h *s3RemoteStore) get(s string) (io.ReadCloser, int64, error) {
	u := h.url(s)

	svc := s3.New(h.session)
	res, err := svc.GetObject(&s3.GetObjectInput{
		Bucket: aws.String("bucket"),
		Key:    aws.String(u),
	})
	if err != nil {
		return nil, 0, &url.Error{
			Op:  "GET",
			URL: u,
			Err: err,
		}
	}

	return res.Body, *res.ContentLength, nil
}

func (h *s3RemoteStore) url(path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return h.baseURL + path
}
