package recording

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Store is a destination for recording (asciicast) blobs. Create returns a
// writer the Recorder streams into; closing it finalizes the blob.
type Store interface {
	Create(ctx context.Context, key string) (io.WriteCloser, error)
}

// FileStore writes recordings under a local root directory. Used in dev/tests.
type FileStore struct{ Root string }

// NewFileStore returns a FileStore rooted at root (created if absent).
func NewFileStore(root string) (*FileStore, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("recording: mkdir %s: %w", root, err)
	}
	return &FileStore{Root: root}, nil
}

// Create opens root/key for writing, creating parent directories.
func (s *FileStore) Create(_ context.Context, key string) (io.WriteCloser, error) {
	path := filepath.Join(s.Root, filepath.Clean("/"+key))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
}

// S3Store streams recordings to an S3/MinIO bucket. Recordings can be large, so
// the object is uploaded with an unknown size (streaming), never buffered.
type S3Store struct {
	client *minio.Client
	bucket string
}

// S3Config configures an S3Store.
type S3Config struct {
	Endpoint  string
	AccessKey string
	SecretKey string
	Bucket    string
	UseSSL    bool
}

// NewS3Store connects and ensures the bucket exists.
func NewS3Store(ctx context.Context, cfg S3Config) (*S3Store, error) {
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("recording: minio client: %w", err)
	}
	exists, err := client.BucketExists(ctx, cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("recording: bucket check: %w", err)
	}
	if !exists {
		if err := client.MakeBucket(ctx, cfg.Bucket, minio.MakeBucketOptions{}); err != nil {
			return nil, fmt.Errorf("recording: make bucket %s: %w", cfg.Bucket, err)
		}
	}
	return &S3Store{client: client, bucket: cfg.Bucket}, nil
}

// Create returns a writer that streams into an object at key. Close waits for
// the upload to finish and returns any upload error.
func (s *S3Store) Create(ctx context.Context, key string) (io.WriteCloser, error) {
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		_, err := s.client.PutObject(ctx, s.bucket, key, pr, -1,
			minio.PutObjectOptions{ContentType: "application/x-asciicast"})
		// Ensure the writer side unblocks if the upload fails early.
		_ = pr.CloseWithError(err)
		done <- err
	}()
	return &pipeUpload{pw: pw, done: done}, nil
}

type pipeUpload struct {
	pw   *io.PipeWriter
	done chan error
}

func (u *pipeUpload) Write(p []byte) (int, error) { return u.pw.Write(p) }

func (u *pipeUpload) Close() error {
	if err := u.pw.Close(); err != nil {
		return err
	}
	return <-u.done
}
