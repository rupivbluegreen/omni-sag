// Command omni-sag is the gateway daemon. Slice 1 boots the walking skeleton:
// SSH front door -> LDAPS auth -> policy-gated dialer -> evidence.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/api"
	"github.com/rupivbluegreen/omni-sag/internal/approval"
	"github.com/rupivbluegreen/omni-sag/internal/authn"
	"github.com/rupivbluegreen/omni-sag/internal/config"
	"github.com/rupivbluegreen/omni-sag/internal/dialer"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/fips"
	"github.com/rupivbluegreen/omni-sag/internal/inspect"
	"github.com/rupivbluegreen/omni-sag/internal/inspectgate"
	"github.com/rupivbluegreen/omni-sag/internal/metrics"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"github.com/rupivbluegreen/omni-sag/internal/policysource"
	"github.com/rupivbluegreen/omni-sag/internal/recording"
	"github.com/rupivbluegreen/omni-sag/internal/session"
	"github.com/rupivbluegreen/omni-sag/internal/sessions"
)

var errBadClientCA = errors.New("api: client_ca is not valid PEM")

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

	// FIPS-readiness self-check. In enforce mode this refuses to start unless the
	// runtime is in FIPS-approved crypto mode (GODEBUG=fips140=on or boringcrypto);
	// in warn/off it only reports. Runs before anything touches crypto so the
	// posture is decided at the very top of boot.
	fipsReport, err := fips.Check(cfg.FIPSMode())
	if err != nil {
		return err
	}
	log.Printf("omni-sag: %s", fipsReport.Summary())
	for _, w := range fipsReport.Warnings {
		log.Printf("omni-sag: FIPS warning: %s", w)
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
	var sessOpts []session.Option // collected here, appended to `opts` further down where session.Option values are built
	if ca := cfg.CyberArk; ca != nil {
		prov, err := dialer.NewCyberArkProvider(dialer.CyberArkParams{
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
		dopts = append(dopts, dialer.WithCredentialProvider(prov))
		sessOpts = append(sessOpts, session.WithCredentialProvider(prov))
		log.Printf("omni-sag: CyberArk credential injection enabled (CCP %s)", ca.BaseURL)
	}

	// Four-eyes approval store (leaf, shared with the API). The dialer blocks an
	// approval-gated target on it; the API decides requests. The data path never
	// imports the API.
	var approvalStore approval.Store
	if cfg.Approval != nil {
		if cfg.Approval.UseCRD {
			approvalStore = approval.CRDStore{}
		} else {
			fs, err := approval.NewFileStore(cfg.Approval.StorePath)
			if err != nil {
				return err
			}
			approvalStore = fs
		}
		dopts = append(dopts, dialer.WithApprovals(approvalStore, time.Duration(cfg.Approval.ApprovalTTL())*time.Second))
		log.Printf("omni-sag: four-eyes approvals enabled")
	}

	// Metrics: count security events by decorating the evidence sinks (no
	// data-path hot-loop instrumentation; metrics is a leaf that never imports
	// the control plane). Exposed on its own listener below.
	met := metrics.New()
	d := dialer.New(cfg.CompilePolicy(), met.CountingSink(ev.dialerSink), dopts...)

	// Policy hot-reload: watch the policy file and atomically swap the dialer's
	// policy (and the API's read view) without dropping in-flight sessions.
	holder := policy.NewHolder(cfg.CompilePolicy())
	polPath := cfgPath
	if cfg.PolicySrc != nil && cfg.PolicySrc.File != "" {
		polPath = cfg.PolicySrc.File
	}
	go policysource.NewFileSource(polPath, 0).Watch(ctx, func(p policy.Policy) {
		holder.Store(p)
		d.SetPolicy(p)
	})

	// Registry of live sessions for the control-plane API (a leaf shared by the
	// session package and the API; the data path never imports the API).
	reg := sessions.NewRegistry()

	var opts []session.Option
	opts = append(opts, session.WithRegistry(reg))
	opts = append(opts, sessOpts...)
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
	srv := session.New(hostKey, auth, d, met.CountingSink(ev.sessionSink), opts...)
	met.SetActiveFn(srv.ActiveSessions)

	// Control-plane API on its OWN listener + goroutine. Its lifecycle is
	// independent of the SSH data path: if it dies, SSH sessions keep running
	// and new ones still connect.
	if cfg.API != nil {
		// Best-effort: the control plane is out-of-band, so a failure to start
		// it (port in use, bad TLS material during a rotation) must NOT take
		// down the SSH data path. Log and continue serving SSH.
		if err := startAPIServer(ctx, cfg.API, reg, holder, approvalStore); err != nil {
			log.Printf("omni-sag: control-plane API did not start (SSH unaffected): %v", err)
		}
	}

	// Metrics endpoint on its own listener (control-plane, out-of-band). A
	// scrape reads only atomic counters, so it cannot stall the SSH data path.
	if cfg.Metrics != nil && cfg.Metrics.Listen != "" {
		startMetricsServer(ctx, cfg.Metrics.Listen, met)
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	log.Printf("omni-sag listening on %s (SSH)", cfg.Listen)

	if err := srv.Serve(ctx, ln); err != nil {
		return err
	}

	// Graceful drain: the listener has stopped accepting; let existing sessions
	// finish up to the grace period, then exit (rolling-upgrade friendly).
	grace := time.Duration(cfg.DrainGraceSeconds()) * time.Second
	log.Printf("omni-sag: draining, waiting up to %s for %d active session(s)", grace, srv.ActiveSessions())
	if n, err := srv.Drain(grace); err != nil {
		log.Printf("omni-sag: %v; exiting", err)
	} else {
		log.Printf("omni-sag: drained cleanly (%d sessions remained)", n)
	}
	return nil
}

// startMetricsServer serves Prometheus metrics on addr until ctx is cancelled.
func startMetricsServer(ctx context.Context, addr string, met *metrics.Metrics) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", met.Handler())
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("omni-sag: metrics endpoint did not start (SSH unaffected): %v", err)
		return
	}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("omni-sag: metrics endpoint stopped: %v", err)
		}
	}()
	log.Printf("omni-sag: metrics on %s/metrics (out-of-band)", addr)
}

// startAPIServer builds and starts the control-plane API on its own listener.
// It never blocks the caller and never shares state with the SSH data path
// beyond the read-only registry and policy holder.
func startAPIServer(ctx context.Context, cfg *config.APIConfig, reg *sessions.Registry, holder *policy.Holder, approvals approval.Store) error {
	authz, err := buildAuthorizer(cfg)
	if err != nil {
		return err
	}
	apiSrv := api.NewServer(api.Config{
		Registry:   reg,
		Policy:     holder.Load,
		Authorizer: authz,
		Approvals:  approvals,
	})
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	httpSrv := &http.Server{Handler: apiSrv.Handler(), ReadHeaderTimeout: 10 * time.Second}

	tlsCfg, err := apiTLSConfig(cfg)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = httpSrv.Close()
	}()
	go func() {
		var serr error
		if tlsCfg != nil {
			httpSrv.TLSConfig = tlsCfg
			serr = httpSrv.ServeTLS(ln, "", "")
		} else {
			serr = httpSrv.Serve(ln)
		}
		if serr != nil && serr != http.ErrServerClosed {
			log.Printf("omni-sag: control-plane API stopped: %v", serr)
		}
	}()
	log.Printf("omni-sag: control-plane API on %s (out-of-band)", cfg.Listen)
	return nil
}

// buildAuthorizer prefers mTLS (client-cert CN -> role) when cn_roles are set,
// otherwise static bearer tokens.
func buildAuthorizer(cfg *config.APIConfig) (api.Authorizer, error) {
	if len(cfg.CNRoles) > 0 {
		m := make(map[string]api.Role, len(cfg.CNRoles))
		for _, c := range cfg.CNRoles {
			m[c.CN] = api.Role(c.Role)
		}
		return api.NewMTLSAuthorizer(m), nil
	}
	m := make(map[string]api.Identity, len(cfg.Tokens))
	for _, t := range cfg.Tokens {
		m[t.Token] = api.Identity{Subject: t.Subject, Role: api.Role(t.Role)}
	}
	return api.NewTokenAuthorizer(m), nil
}

// apiTLSConfig builds the server TLS config: server cert (required for HTTPS)
// plus, when client_ca is set, mandatory client-cert verification (mTLS).
func apiTLSConfig(cfg *config.APIConfig) (*tls.Config, error) {
	if cfg.TLSCert == "" {
		return nil, nil // dev: plain HTTP + bearer token
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return nil, err
	}
	tc := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if cfg.ClientCA != "" {
		caPEM, err := os.ReadFile(cfg.ClientCA)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errBadClientCA
		}
		tc.ClientCAs = pool
		tc.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tc, nil
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
