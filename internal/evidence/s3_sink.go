package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// S3Config configures the S3/MinIO evidence sink.
type S3Config struct {
	Endpoint  string // host:port, no scheme, e.g. "localhost:9000"
	AccessKey string
	SecretKey string
	Bucket    string
	UseSSL    bool
}

// S3Sink writes each event as an individual object under a time-ordered key.
// This is the crude Slice 1 form; Slice 3 replaces per-event objects with
// batched, Merkle-chained, Object-Locked segments.
type S3Sink struct {
	mu     sync.Mutex
	client *minio.Client
	bucket string
}

// NewS3Sink connects to the endpoint and ensures the bucket exists.
func NewS3Sink(ctx context.Context, cfg S3Config) (*S3Sink, error) {
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("evidence: minio client: %w", err)
	}
	exists, err := client.BucketExists(ctx, cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("evidence: bucket check: %w", err)
	}
	if !exists {
		if err := client.MakeBucket(ctx, cfg.Bucket, minio.MakeBucketOptions{}); err != nil {
			return nil, fmt.Errorf("evidence: make bucket %s: %w", cfg.Bucket, err)
		}
	}
	return &S3Sink{client: client, bucket: cfg.Bucket}, nil
}

// Emit uploads one event object. Key is time-prefixed for lexical ordering.
func (s *S3Sink) Emit(e Event) error {
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	body, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("evidence: marshal: %w", err)
	}
	key := fmt.Sprintf("events/%s-%s.json", e.Time.UTC().Format("20060102T150405.000000000Z"), e.ID)

	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.client.PutObject(context.Background(), s.bucket, key,
		bytes.NewReader(body), int64(len(body)),
		minio.PutObjectOptions{ContentType: "application/json"})
	if err != nil {
		return fmt.Errorf("evidence: put %s: %w", key, err)
	}
	return nil
}

// Close is a no-op for the S3 sink.
func (s *S3Sink) Close() error { return nil }
