package blob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const MaxSize = 32 << 20

type Store interface {
	Put(context.Context, string, []byte) error
	Get(context.Context, string) ([]byte, error)
	Delete(context.Context, string) error
}
type S3 struct {
	Client              *s3.Client
	Bucket, Prefix, KMS string
}

func FromEnv(ctx context.Context) (Store, error) {
	bucket := os.Getenv("OBJECT_STORE_BUCKET")
	if bucket == "" {
		return nil, nil
	}
	region := os.Getenv("OBJECT_STORE_REGION")
	if region == "" {
		return nil, errors.New("OBJECT_STORE_REGION required")
	}
	endpoint := os.Getenv("OBJECT_STORE_ENDPOINT")
	if endpoint != "" {
		u, e := url.Parse(endpoint)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" {
			return nil, errors.New("object endpoint must be an HTTPS URL without credentials or query")
		}
	}
	prefix := os.Getenv("OBJECT_STORE_PREFIX")
	if strings.Contains(prefix, "..") || strings.HasPrefix(prefix, "/") {
		return nil, errors.New("invalid object prefix")
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region), config.WithRetryMaxAttempts(2))
	if err != nil {
		return nil, errors.New("object store configuration unavailable")
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
			o.UsePathStyle = true
		}
	})
	return &S3{Client: client, Bucket: bucket, Prefix: prefix, KMS: os.Getenv("OBJECT_STORE_SSE_KMS_KEY_ID")}, nil
}
func (s *S3) Put(ctx context.Context, key string, raw []byte) error {
	if len(raw) > MaxSize {
		return errors.New("evidence object exceeds size limit")
	}
	input := &s3.PutObjectInput{Bucket: &s.Bucket, Key: aws.String(s.Prefix + key), Body: bytes.NewReader(raw), ContentType: aws.String("application/json"), ServerSideEncryption: types.ServerSideEncryptionAes256}
	if s.KMS != "" {
		input.ServerSideEncryption = types.ServerSideEncryptionAwsKms
		input.SSEKMSKeyId = &s.KMS
	}
	if _, err := s.Client.PutObject(ctx, input); err != nil {
		return errors.New("evidence object upload failed")
	}
	return nil
}
func (s *S3) Get(ctx context.Context, key string) ([]byte, error) {
	out, err := s.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.Bucket, Key: aws.String(s.Prefix + key)})
	if err != nil {
		return nil, errors.New("evidence object read failed")
	}
	defer out.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(out.Body, MaxSize+1))
	if err != nil || len(raw) > MaxSize {
		return nil, errors.New("evidence object invalid or oversized")
	}
	return raw, nil
}
func (s *S3) Delete(ctx context.Context, key string) error {
	if _, err := s.Client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.Bucket, Key: aws.String(s.Prefix + key)}); err != nil {
		return errors.New("orphan object deletion failed")
	}
	return nil
}
func Verify(raw []byte, digest string) error {
	sum := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return errors.New("evidence object digest mismatch")
	}
	return nil
}
