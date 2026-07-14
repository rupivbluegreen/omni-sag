package inspectgate

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// S3Config configures an S3/MinIO blob store.
type S3Config struct {
	Endpoint  string
	AccessKey string
	SecretKey string
	Bucket    string
	UseSSL    bool
}

// PlainStore is a non-locked S3 bucket used as the transient holding area for
// large files being inspected. Objects here are deletable (released or promoted
// to quarantine once a verdict is known).
type PlainStore struct {
	client *minio.Client
	bucket string
}

// NewPlainStore connects and ensures the bucket exists.
func NewPlainStore(ctx context.Context, cfg S3Config) (*PlainStore, error) {
	client, err := newClient(cfg)
	if err != nil {
		return nil, err
	}
	if err := ensureBucket(ctx, client, cfg.Bucket, false); err != nil {
		return nil, err
	}
	return &PlainStore{client: client, bucket: cfg.Bucket}, nil
}

func (s *PlainStore) Put(ctx context.Context, key, contentType string, r io.Reader, size int64) error {
	_, err := s.client.PutObject(ctx, s.bucket, key, r, size, minio.PutObjectOptions{ContentType: contentType})
	if err != nil {
		return fmt.Errorf("holding put %s: %w", key, err)
	}
	return nil
}

func (s *PlainStore) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	return obj, nil
}

func (s *PlainStore) Delete(ctx context.Context, key string) error {
	return s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{})
}

// WORMStore is an Object-Locked bucket used to quarantine blocked content. Each
// object is written once with a retention date and cannot be deleted or
// overwritten within the retention window.
type WORMStore struct {
	client        *minio.Client
	bucket        string
	mode          minio.RetentionMode
	retentionDays int
}

// WORMConfig configures a WORMStore.
type WORMConfig struct {
	S3Config
	Compliance    bool // true => COMPLIANCE (default), false => GOVERNANCE
	RetentionDays int
}

// NewWORMStore connects and ensures an Object-Lock-enabled bucket exists.
func NewWORMStore(ctx context.Context, cfg WORMConfig) (*WORMStore, error) {
	client, err := newClient(cfg.S3Config)
	if err != nil {
		return nil, err
	}
	if err := ensureBucket(ctx, client, cfg.Bucket, true); err != nil {
		return nil, err
	}
	mode := minio.Compliance
	if !cfg.Compliance {
		mode = minio.Governance
	}
	days := cfg.RetentionDays
	if days <= 0 {
		days = 3650
	}
	return &WORMStore{client: client, bucket: cfg.Bucket, mode: mode, retentionDays: days}, nil
}

func (s *WORMStore) Put(ctx context.Context, key, contentType string, r io.Reader, size int64) error {
	until := time.Now().UTC().Add(time.Duration(s.retentionDays) * 24 * time.Hour)
	_, err := s.client.PutObject(ctx, s.bucket, key, r, size, minio.PutObjectOptions{
		ContentType:     contentType,
		Mode:            s.mode,
		RetainUntilDate: until,
	})
	if err != nil {
		return fmt.Errorf("quarantine put %s: %w", key, err)
	}
	return nil
}

func (s *WORMStore) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	return s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
}

// Delete on a WORM store is a no-op-ish attempt: within retention it will fail,
// which is the point. Included to satisfy BlobStore; quarantine is never
// deleted by the gate.
func (s *WORMStore) Delete(ctx context.Context, key string) error {
	return s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{})
}

func newClient(cfg S3Config) (*minio.Client, error) {
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("inspectgate: minio client: %w", err)
	}
	return client, nil
}

func ensureBucket(ctx context.Context, client *minio.Client, bucket string, objectLock bool) error {
	exists, err := client.BucketExists(ctx, bucket)
	if err != nil {
		return fmt.Errorf("inspectgate: bucket check %s: %w", bucket, err)
	}
	if !exists {
		if err := client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{ObjectLocking: objectLock}); err != nil {
			return fmt.Errorf("inspectgate: make bucket %s: %w", bucket, err)
		}
		return nil
	}
	if objectLock {
		if _, _, _, _, err := client.GetObjectLockConfig(ctx, bucket); err != nil {
			return fmt.Errorf("inspectgate: bucket %s exists but Object Lock is not enabled: %w", bucket, err)
		}
	}
	return nil
}
