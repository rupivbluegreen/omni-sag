package evidence

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// WORMMode selects the S3 Object Lock retention mode.
type WORMMode string

const (
	// WORMCompliance cannot be shortened or bypassed by anyone, including root.
	// This is the correct default for evidence.
	WORMCompliance WORMMode = "COMPLIANCE"
	// WORMGovernance can be bypassed with the s3:BypassGovernanceRetention
	// permission. Useful for dev/conformance so test objects can be cleaned up.
	WORMGovernance WORMMode = "GOVERNANCE"
)

// WORMConfig configures the Object-Locked S3/MinIO evidence store.
type WORMConfig struct {
	Endpoint      string
	AccessKey     string
	SecretKey     string
	Bucket        string
	UseSSL        bool
	Mode          WORMMode
	RetentionDays int
}

// WORMUploader writes sealed segments and checkpoints to an Object-Locked
// (WORM) bucket. Each object is written once with a retention date; within the
// retention window it cannot be deleted or overwritten in place.
//
// NOTE: verified against MinIO. Dell ECS implements S3 Object Lock with known
// divergences (default-retention handling, legal-hold semantics); this code is
// structured so a conformance run can be pointed at ECS later, but ECS is
// UNTESTED here.
type WORMUploader struct {
	client        *minio.Client
	bucket        string
	mode          minio.RetentionMode
	retentionDays int
}

// NewWORMUploader connects to the endpoint and ensures an Object-Lock-enabled
// bucket exists. A bucket that exists but does not have Object Lock enabled is
// rejected (Object Lock can only be set at creation time).
func NewWORMUploader(ctx context.Context, cfg WORMConfig) (*WORMUploader, error) {
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("evidence worm: client: %w", err)
	}

	exists, err := client.BucketExists(ctx, cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("evidence worm: bucket check: %w", err)
	}
	if !exists {
		if err := client.MakeBucket(ctx, cfg.Bucket, minio.MakeBucketOptions{ObjectLocking: true}); err != nil {
			return nil, fmt.Errorf("evidence worm: make locked bucket %s: %w", cfg.Bucket, err)
		}
	} else {
		if _, _, _, _, err := client.GetObjectLockConfig(ctx, cfg.Bucket); err != nil {
			return nil, fmt.Errorf("evidence worm: bucket %s exists but Object Lock is not enabled (must be set at creation): %w", cfg.Bucket, err)
		}
	}

	mode := minio.Compliance
	if cfg.Mode == WORMGovernance {
		mode = minio.Governance
	}
	days := cfg.RetentionDays
	if days <= 0 {
		days = 3650 // 10 years default for evidence
	}
	return &WORMUploader{client: client, bucket: cfg.Bucket, mode: mode, retentionDays: days}, nil
}

func (w *WORMUploader) retainUntil() time.Time {
	return time.Now().UTC().Add(time.Duration(w.retentionDays) * 24 * time.Hour)
}

func (w *WORMUploader) put(name string, r *bytes.Reader, contentType string) error {
	until := w.retainUntil()
	_, err := w.client.PutObject(context.Background(), w.bucket, name, r, int64(r.Len()),
		minio.PutObjectOptions{
			ContentType:     contentType,
			Mode:            w.mode,
			RetainUntilDate: until,
		})
	if err != nil {
		return fmt.Errorf("evidence worm: put %s: %w", name, err)
	}
	return nil
}

// PutSegment uploads a sealed segment file under key "segments/<name>".
func (w *WORMUploader) PutSegment(name, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("evidence worm: read segment %s: %w", path, err)
	}
	return w.put("segments/"+name, bytes.NewReader(data), "application/x-ndjson")
}

// PutCheckpoint uploads a checkpoint under key "checkpoints/<name>".
func (w *WORMUploader) PutCheckpoint(name string, data []byte) error {
	return w.put("checkpoints/"+name, bytes.NewReader(data), "application/json")
}
