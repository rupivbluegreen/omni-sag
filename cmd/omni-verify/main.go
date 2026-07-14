// Command omni-verify is the offline evidence verifier. Given an evidence
// bundle (segments + checkpoints) and, optionally, a pinned public key and/or
// expected chain head, it recomputes hashes and Merkle roots, verifies the
// record and global checkpoint chains, per-emitter sequence continuity, and
// every checkpoint signature — with NO running gateway.
//
// Exit codes:
//
//	0  PASS   — intact AND authentic (a key was pinned and matched)
//	1  FAIL   — tampering detected (an integrity check failed)
//	2  usage/IO error
//	3  UNVERIFIED — intact but NOT authenticated (no -pubkey pinned). Without a
//	   pinned key, a forged bundle re-signed with another key also passes the
//	   internal checks, so authenticity cannot be asserted.
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
	pubkey := flag.String("pubkey", "", "pinned Ed25519 public key (hex or file). Required to assert authenticity.")
	head := flag.String("head", "", "expected latest-checkpoint hash (hex or file), pinned out of band to detect trailing truncation")
	flag.Parse()

	if *bundle == "" {
		fmt.Fprintln(os.Stderr, "usage: omni-verify -bundle <dir> [-pubkey <hex|file>] [-head <hex|file>]")
		os.Exit(2)
	}

	pinned, err := resolveArg(*pubkey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "omni-verify: pubkey: %v\n", err)
		os.Exit(2)
	}
	expectedHead, err := resolveArg(*head)
	if err != nil {
		fmt.Fprintf(os.Stderr, "omni-verify: head: %v\n", err)
		os.Exit(2)
	}

	rep, err := evidence.VerifyBundle(*bundle, pinned, expectedHead)
	if err != nil {
		fmt.Fprintf(os.Stderr, "omni-verify: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("records:     %d\n", rep.RecordsChecked)
	fmt.Printf("segments:    %d\n", rep.SegmentsChecked)
	fmt.Printf("checkpoints: %d\n", rep.CheckpointsChecked)
	fmt.Printf("signing key: %s\n", strings.Join(rep.SigningKeys, ", "))
	fmt.Printf("chain head:  %s\n", rep.ChainHead)

	if !rep.OK {
		fmt.Fprintln(os.Stderr, "\nFAIL — evidence bundle verification failed:")
		for _, p := range rep.Problems {
			fmt.Fprintf(os.Stderr, "  - %s\n", p)
		}
		os.Exit(1)
	}

	// Integrity passed. Authenticity depends on a pinned key.
	if !rep.KeyPinned {
		fmt.Fprintln(os.Stderr, "\nUNVERIFIED — records are internally consistent, but authenticity was NOT checked:")
		fmt.Fprintln(os.Stderr, "  no -pubkey pinned. A forged bundle re-signed with another key would also pass.")
		fmt.Fprintln(os.Stderr, "  Re-run with -pubkey <gateway key delivered out of band> to verify authenticity.")
		os.Exit(3)
	}

	msg := "PASS — evidence bundle is intact and authentic."
	if !rep.HeadPinned {
		msg += "\n(note: no -head pinned; trailing truncation of the newest checkpoint(s) is only" +
			"\n prevented by WORM. Pin -head " + rep.ChainHead + " next time to detect it offline.)"
	}
	fmt.Println("\n" + msg)
	os.Exit(0)
}

// resolveArg accepts a hex value directly, or a path to a file whose contents
// are the hex value. Empty stays empty (feature not pinned).
func resolveArg(v string) (string, error) {
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
