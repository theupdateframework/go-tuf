package client

import (
	"fmt"
	"io"
	"net/url"
	"path"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

// S3RemoteOptions allows configuring the metadata and targets paths.
// Default metadata path: ""
// Default targets path:  "targets"
type S3RemoteOptions struct {
	MetadataPath string
	TargetsPath  string
}

// S3RemoteStore is a RemoteStore implementation using S3. The base url is
// interpreted as the bucket name. Region must be set in an AWS_REGION
// environment variable. Credentials must be set by environment variables or
// a credentials file as used by awscli.
func S3RemoteStore(baseURL string, opts *S3RemoteOptions) (RemoteStore, error) {
	url, err := url.Parse(baseURL)
	if err != nil {
		return nil, ErrInvalidURL{baseURL}
	}
	if url.Scheme != "s3" {
		return nil, ErrInvalidURL{baseURL}
	}
	bucketName := url.Host

	if opts == nil {
		opts = &S3RemoteOptions{}
	}
	if opts.TargetsPath == "" {
		opts.TargetsPath = "targets"
	}

	session := session.New(&aws.Config{})
	return &s3RemoteStore{bucketName, opts, session}, nil
}

type s3RemoteStore struct {
	bucketName string
	opts       *S3RemoteOptions
	session    *session.Session
}

func (s *s3RemoteStore) GetMeta(name string) (io.ReadCloser, int64, error) {
	return s.get(path.Join(s.opts.MetadataPath, name))
}

func (s *s3RemoteStore) GetTarget(name string) (io.ReadCloser, int64, error) {
	return s.get(path.Join(s.opts.TargetsPath, name))
}

func (s *s3RemoteStore) get(p string) (io.ReadCloser, int64, error) {
	svc := s3.New(s.session)
	res, err := svc.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(p),
	})
	if err != nil {
		return nil, 0, &url.Error{
			Op:  "GET",
			URL: fmt.Sprintf("s3://%s/%s", s.bucketName, p),
			Err: err,
		}
	}

	return res.Body, *res.ContentLength, nil
}
