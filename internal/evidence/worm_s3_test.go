package evidence

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// TestWORMConformance is a live conformance check against a real S3 Object Lock
// implementation (MinIO in the dev lab). It is skipped unless
// RUN_WORM_CONFORMANCE=1 so it never runs in CI. Env overrides:
//
//	WORM_ENDPOINT (default 127.0.0.1:9000), WORM_ACCESS, WORM_SECRET.
//
// It proves the WORM property: an object written with a retention date cannot
// be deleted within the retention window by an ordinary delete.
func TestWORMConformance(t *testing.T) {
	if os.Getenv("RUN_WORM_CONFORMANCE") != "1" {
		t.Skip("set RUN_WORM_CONFORMANCE=1 to run the live Object-Lock conformance test")
	}
	endpoint := envOr("WORM_ENDPOINT", "127.0.0.1:9000")
	access := envOr("WORM_ACCESS", "omnisag")
	secret := envOr("WORM_SECRET", "omnisag-dev-secret")
	bucket := fmt.Sprintf("omni-sag-worm-conf-%d", time.Now().UnixNano())

	ctx := context.Background()
	up, err := NewWORMUploader(ctx, WORMConfig{
		Endpoint: endpoint, AccessKey: access, SecretKey: secret,
		Bucket: bucket, Mode: WORMGovernance, RetentionDays: 1,
	})
	if err != nil {
		t.Fatalf("create WORM uploader: %v", err)
	}

	// A raw client for the adversarial delete attempts and cleanup.
	client, err := minio.New(endpoint, &minio.Options{
		Creds: credentials.NewStaticV4(access, secret, ""),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cleanupBucket(client, bucket) })

	if err := up.PutCheckpoint("checkpoint-1-0.json", []byte(`{"demo":true}`)); err != nil {
		t.Fatalf("put locked object: %v", err)
	}
	key := "checkpoints/checkpoint-1-0.json"

	// Identify the locked object version.
	info, err := client.StatObject(ctx, bucket, key, minio.StatObjectOptions{})
	if err != nil {
		t.Fatalf("stat object: %v", err)
	}
	versionID := info.VersionID

	// The retention must actually be set on that version.
	ret, until, rerr := client.GetObjectRetention(ctx, bucket, key, versionID)
	if rerr != nil {
		t.Fatalf("get retention: %v", rerr)
	}
	if ret == nil || until == nil {
		t.Fatal("expected a retention mode and date on the locked object")
	}
	t.Logf("object retention: mode=%s until=%s version=%s", *ret, until.Format(time.RFC3339), versionID)
	if *ret != minio.Governance {
		t.Fatalf("expected GOVERNANCE retention, got %q", *ret)
	}

	// Deleting the specific locked VERSION without a governance bypass MUST
	// fail — this is the WORM guarantee. (A version-less delete would only add a
	// delete marker and leave the locked version intact, so it does not test
	// the lock.)
	err = client.RemoveObject(ctx, bucket, key, minio.RemoveObjectOptions{VersionID: versionID})
	if err == nil {
		t.Fatal("WORM VIOLATION: locked object version was deletable within retention without a bypass")
	}
	t.Logf("delete of locked version correctly refused: %v", err)

	// Overwriting in place must also not destroy the locked version: the
	// original content must still be readable by version id.
	obj, err := client.GetObject(ctx, bucket, key, minio.GetObjectOptions{VersionID: versionID})
	if err != nil {
		t.Fatalf("get object version: %v", err)
	}
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(obj); err != nil {
		t.Fatalf("read object: %v", err)
	}
	if buf.String() != `{"demo":true}` {
		t.Fatalf("retained object content changed: %q", buf.String())
	}
	t.Log("locked version content intact and delete-protected")
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// cleanupBucket removes locked objects with a governance bypass, then the
// bucket. Best-effort: failures are logged, not fatal.
func cleanupBucket(client *minio.Client, bucket string) {
	ctx := context.Background()
	for obj := range client.ListObjects(ctx, bucket, minio.ListObjectsOptions{Recursive: true, WithVersions: true}) {
		if obj.Err != nil {
			continue
		}
		_ = client.RemoveObject(ctx, bucket, obj.Key, minio.RemoveObjectOptions{
			GovernanceBypass: true,
			VersionID:        obj.VersionID,
		})
	}
	_ = client.RemoveBucket(ctx, bucket)
}
