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
	"time"

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

	ev, err := buildEvidence(ctx, cfg.Evidence)
	if err != nil {
		return err
	}
	defer ev.close()

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

	d := dialer.New(cfg.CompilePolicy(), ev.dialerSink)

	var opts []session.Option
	if cfg.MFA.Enabled {
		rc := cfg.MFA.RADIUS
		opts = append(opts, session.WithMFA(authn.NewRADIUS(authn.RADIUSConfig{
			Server:                    rc.Server,
			Secret:                    []byte(rc.Secret),
			NASIdentifier:             rc.NASIdentifier,
			Timeout:                   time.Duration(rc.TimeoutSeconds) * time.Second,
			Retries:                   rc.Retries,
			AllowInteractiveChallenge: rc.AllowInteractiveChallenge,
		})))
		log.Printf("omni-sag: MFA enabled (RADIUS %s)", rc.Server)
	}
	srv := session.New(hostKey, auth, d, ev.sessionSink, opts...)

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	log.Printf("omni-sag listening on %s (SSH)", cfg.Listen)

	err = srv.Serve(ctx, ln)
	log.Printf("omni-sag: shutting down")
	return err
}

// evidenceSystem holds the sinks handed to the dialer and session plus a close
// hook. In pipeline mode the two sinks are distinct per-emitter handles on one
// bus, giving each subsystem its own gap-detectable sequence; in the crude
// Slice-1 modes both point at the same simple sink.
type evidenceSystem struct {
	dialerSink  evidence.Sink
	sessionSink evidence.Sink
	closer      func() error
}

func (e evidenceSystem) close() {
	if e.closer != nil {
		if err := e.closer(); err != nil {
			log.Printf("omni-sag: evidence close: %v", err)
		}
	}
}

func buildEvidence(ctx context.Context, ec config.EvidenceConfig) (evidenceSystem, error) {
	if p := ec.Pipeline; p != nil {
		signer, err := evidence.LoadOrCreateSigner(p.SigningKey)
		if err != nil {
			return evidenceSystem{}, err
		}
		var worm *evidence.WORMUploader
		if p.WORM != nil {
			mode := evidence.WORMCompliance
			if p.WORM.Mode == "GOVERNANCE" {
				mode = evidence.WORMGovernance
			}
			worm, err = evidence.NewWORMUploader(ctx, evidence.WORMConfig{
				Endpoint:      p.WORM.Endpoint,
				AccessKey:     p.WORM.AccessKey,
				SecretKey:     p.WORM.SecretKey,
				Bucket:        p.WORM.Bucket,
				UseSSL:        p.WORM.UseSSL,
				Mode:          mode,
				RetentionDays: p.WORM.RetentionDays,
			})
			if err != nil {
				return evidenceSystem{}, err
			}
		}
		bus, err := evidence.NewBus(evidence.BusConfig{
			DataDir:     p.DataDir,
			SegmentSize: p.SegmentSize,
			Signer:      signer,
			WORM:        worm,
		})
		if err != nil {
			return evidenceSystem{}, err
		}
		log.Printf("omni-sag: evidence pipeline active (data_dir=%s, signing key=%s)", p.DataDir, signer.PublicKeyHex()[:16])
		return evidenceSystem{
			dialerSink:  bus.Emitter("dialer"),
			sessionSink: bus.Emitter("session"),
			closer:      bus.Close,
		}, nil
	}

	// Crude Slice-1 sinks: one shared sink for both subsystems.
	var sink evidence.Sink
	var err error
	if ec.S3 != nil {
		sink, err = evidence.NewS3Sink(ctx, evidence.S3Config{
			Endpoint:  ec.S3.Endpoint,
			AccessKey: ec.S3.AccessKey,
			SecretKey: ec.S3.SecretKey,
			Bucket:    ec.S3.Bucket,
			UseSSL:    ec.S3.UseSSL,
		})
	} else {
		sink, err = evidence.NewFileSink(ec.File)
	}
	if err != nil {
		return evidenceSystem{}, err
	}
	return evidenceSystem{dialerSink: sink, sessionSink: sink, closer: sink.Close}, nil
}
