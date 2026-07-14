// Command omni-verify is the offline evidence verifier. Given an evidence
// bundle (segments + checkpoints) and, optionally, a pinned public key, it
// recomputes hashes and Merkle roots, verifies the hash chain and per-emitter
// sequence continuity, and checks every checkpoint signature — with NO running
// gateway. It exits 0 on PASS and non-zero on FAIL.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
)

func main() {
	bundle := flag.String("bundle", "", "path to the evidence bundle directory (contains segments/ and checkpoints/)")
	pubkey := flag.String("pubkey", "", "optional pinned Ed25519 public key: hex string or path to a file containing it")
	flag.Parse()

	if *bundle == "" {
		fmt.Fprintln(os.Stderr, "usage: omni-verify -bundle <dir> [-pubkey <hex|file>]")
		os.Exit(2)
	}

	pinned, err := resolvePubKey(*pubkey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "omni-verify: %v\n", err)
		os.Exit(2)
	}

	rep, err := evidence.VerifyBundle(*bundle, pinned)
	if err != nil {
		fmt.Fprintf(os.Stderr, "omni-verify: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("records:     %d\n", rep.RecordsChecked)
	fmt.Printf("segments:    %d\n", rep.SegmentsChecked)
	fmt.Printf("checkpoints: %d\n", rep.CheckpointsChecked)
	fmt.Printf("signing key: %s\n", strings.Join(rep.SigningKeys, ", "))

	if rep.OK {
		fmt.Println("\nPASS — evidence bundle is intact and authentic.")
		os.Exit(0)
	}

	fmt.Fprintln(os.Stderr, "\nFAIL — evidence bundle verification failed:")
	for _, p := range rep.Problems {
		fmt.Fprintf(os.Stderr, "  - %s\n", p)
	}
	os.Exit(1)
}

// resolvePubKey accepts a hex key directly, or a path to a file whose contents
// are the hex key. Empty means "trust the embedded keys but require internal
// consistency".
func resolvePubKey(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	if info, err := os.Stat(v); err == nil && !info.IsDir() {
		data, err := os.ReadFile(v)
		if err != nil {
			return "", fmt.Errorf("read pubkey file: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	return strings.TrimSpace(v), nil
}
