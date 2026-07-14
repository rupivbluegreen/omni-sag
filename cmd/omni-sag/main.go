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
	"github.com/rupivbluegreen/omni-sag/internal/inspect"
	"github.com/rupivbluegreen/omni-sag/internal/inspectgate"
	"github.com/rupivbluegreen/omni-sag/internal/recording"
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

	var dopts []dialer.Option
	if ca := cfg.CyberArk; ca != nil {
		opt, err := dialer.WithCyberArk(dialer.CyberArkParams{
			BaseURL:                ca.BaseURL,
			ClientCert:             ca.ClientCertPath,
			ClientKey:              ca.ClientKeyPath,
			CACert:                 ca.CACertPath,
			AppID:                  ca.AppID,
			Safe:                   ca.Safe,
			ObjectTemplate:         ca.ObjectTemplate,
			TimeoutSeconds:         ca.TimeoutSeconds,
			BreakerFailures:        ca.BreakerFails,
			BreakerCooldownSeconds: ca.BreakerCoolSec,
		})
		if err != nil {
			return err
		}
		dopts = append(dopts, opt)
		log.Printf("omni-sag: CyberArk credential injection enabled (CCP %s)", ca.BaseURL)
	}
	d := dialer.New(cfg.CompilePolicy(), ev.dialerSink, dopts...)

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
	if cfg.Recording != nil {
		store, err := buildRecordingStore(ctx, cfg.Recording)
		if err != nil {
			return err
		}
		opts = append(opts, session.WithRecording(store))
		log.Printf("omni-sag: session recording enabled")
	}
	if cfg.Inspection != nil && cfg.Inspection.Enabled {
		gate, err := buildInspection(ctx, cfg.Inspection)
		if err != nil {
			return err
		}
		opts = append(opts, session.WithInspection(gate))
		log.Printf("omni-sag: SFTP content inspection enabled (ICAP %s/%s)", cfg.Inspection.ICAP.Endpoint, cfg.Inspection.ICAP.Service)
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

// buildInspection wires the ICAP client, holding area, and quarantine store
// into a content-inspection gate for SFTP uploads.
func buildInspection(ctx context.Context, ic *config.InspectionConfig) (*inspectgate.Gate, error) {
	insp := inspect.New(inspect.Config{
		Endpoint:     ic.ICAP.Endpoint,
		Service:      ic.ICAP.Service,
		PreviewBytes: ic.ICAP.PreviewBytes,
		Timeout:      time.Duration(ic.ICAP.TimeoutSeconds) * time.Second,
	})
	quar, err := inspectgate.NewWORMStore(ctx, inspectgate.WORMConfig{
		S3Config: inspectgate.S3Config{
			Endpoint:  ic.Quarantine.Endpoint,
			AccessKey: ic.Quarantine.AccessKey,
			SecretKey: ic.Quarantine.SecretKey,
			Bucket:    ic.Quarantine.Bucket,
			UseSSL:    ic.Quarantine.UseSSL,
		},
		Compliance:    ic.Quarantine.Mode != "GOVERNANCE",
		RetentionDays: ic.Quarantine.RetentionDays,
	})
	if err != nil {
		return nil, err
	}
	var holding inspectgate.BlobStore
	if ic.Holding != nil {
		h, err := inspectgate.NewPlainStore(ctx, inspectgate.S3Config{
			Endpoint:  ic.Holding.Endpoint,
			AccessKey: ic.Holding.AccessKey,
			SecretKey: ic.Holding.SecretKey,
			Bucket:    ic.Holding.Bucket,
			UseSSL:    ic.Holding.UseSSL,
		})
		if err != nil {
			return nil, err
		}
		holding = h
	}
	return inspectgate.New(inspectgate.Config{
		Inspector:  insp,
		Holding:    holding,
		Quarantine: quar,
		Threshold:  ic.ThresholdBytes,
	})
}

// buildRecordingStore returns the recording store for interactive sessions.
func buildRecordingStore(ctx context.Context, rc *config.RecordingConfig) (recording.Store, error) {
	if rc.S3 != nil {
		return recording.NewS3Store(ctx, recording.S3Config{
			Endpoint:  rc.S3.Endpoint,
			AccessKey: rc.S3.AccessKey,
			SecretKey: rc.S3.SecretKey,
			Bucket:    rc.S3.Bucket,
			UseSSL:    rc.S3.UseSSL,
		})
	}
	return recording.NewFileStore(rc.LocalDir)
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
		log.Printf("omni-sag: evidence pipeline active (data_dir=%s, signing key=%s)", p.DataDir, signer.PublicKeyHex())
		return evidenceSystem{
			dialerSink:  bus.Emitter("dialer"),
			sessionSink: bus.Emitter("session"),
			closer: func() error {
				err := bus.Close()
				// Publish the chain head out of band so operators can pin it as
				// `omni-verify -head <hash>` to detect trailing truncation.
				log.Printf("omni-sag: evidence chain head=%s", bus.Head())
				return err
			},
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
