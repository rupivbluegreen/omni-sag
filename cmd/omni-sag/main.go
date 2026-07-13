// Command omni-sag is the gateway daemon. Slice 1 boots the walking skeleton:
// SSH front door -> LDAPS auth -> policy-gated dialer -> evidence.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os/signal"
	"syscall"

	"github.com/rupivbluegreen/omni-sag/internal/authn"
	"github.com/rupivbluegreen/omni-sag/internal/config"
	"github.com/rupivbluegreen/omni-sag/internal/dialer"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/session"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to configuration file")
	flag.Parse()

	if err := run(*cfgPath); err != nil {
		log.Fatalf("omni-sag: %v", err)
	}
}

func run(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	sink, err := buildSink(ctx, cfg.Evidence)
	if err != nil {
		return err
	}
	defer sink.Close()

	hostKey, err := session.LoadOrCreateHostKey(cfg.HostKey)
	if err != nil {
		return err
	}

	auth := authn.NewLDAP(authn.LDAPConfig{
		URL:          cfg.LDAP.URL,
		BaseDN:       cfg.LDAP.BaseDN,
		BindDN:       cfg.LDAP.BindDN,
		BindPassword: cfg.LDAP.BindPassword,
		UserFilter:   cfg.LDAP.UserFilter,
		InsecureTLS:  cfg.LDAP.InsecureTLS,
	})

	d := dialer.New(cfg.CompilePolicy(), sink)
	srv := session.New(hostKey, auth, d, sink)

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	log.Printf("omni-sag listening on %s (SSH)", cfg.Listen)

	err = srv.Serve(ctx, ln)
	log.Printf("omni-sag: shutting down")
	return err
}

func buildSink(ctx context.Context, ec config.EvidenceConfig) (evidence.Sink, error) {
	if ec.S3 != nil {
		return evidence.NewS3Sink(ctx, evidence.S3Config{
			Endpoint:  ec.S3.Endpoint,
			AccessKey: ec.S3.AccessKey,
			SecretKey: ec.S3.SecretKey,
			Bucket:    ec.S3.Bucket,
			UseSSL:    ec.S3.UseSSL,
		})
	}
	return evidence.NewFileSink(ec.File)
}
