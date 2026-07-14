// Command omnisag-ctl is a thin CLI over the Omni-SAG control-plane SDK
// (internal/api.Client). It lists and terminates live sessions and reads the
// policy. The Bubble Tea TUI (Slice 9) is layered on the same SDK.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/rupivbluegreen/omni-sag/internal/api"
	"github.com/rupivbluegreen/omni-sag/internal/tui"
)

func main() {
	base := flag.String("api", envOr("OMNI_API", "http://127.0.0.1:8443"), "control-plane API base URL")
	token := flag.String("token", os.Getenv("OMNI_TOKEN"), "bearer token")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	c := api.NewClient(*base, *token, nil)
	ctx := context.Background()
	if err := dispatch(ctx, c, args); err != nil {
		fmt.Fprintln(os.Stderr, "omnisag-ctl:", err)
		os.Exit(1)
	}
}

func dispatch(ctx context.Context, c *api.Client, args []string) error {
	switch args[0] {
	case "sessions":
		if len(args) >= 2 && args[1] == "kill" {
			if len(args) < 3 {
				return fmt.Errorf("usage: omnisag-ctl sessions kill <id>")
			}
			if err := c.TerminateSession(ctx, args[2]); err != nil {
				return err
			}
			fmt.Println("terminated", args[2])
			return nil
		}
		list, err := c.ListSessions(ctx)
		if err != nil {
			return err
		}
		return printJSON(list)
	case "approvals":
		list, err := c.ListApprovals(ctx)
		if err != nil {
			return err
		}
		return printJSON(list)
	case "approve":
		if len(args) < 2 {
			return fmt.Errorf("usage: omnisag-ctl approve <id>")
		}
		req, err := c.ApproveApproval(ctx, args[1])
		if err != nil {
			return err
		}
		return printJSON(req)
	case "deny":
		if len(args) < 2 {
			return fmt.Errorf("usage: omnisag-ctl deny <id>")
		}
		req, err := c.DenyApproval(ctx, args[1])
		if err != nil {
			return err
		}
		return printJSON(req)
	case "policy":
		pv, err := c.GetPolicy(ctx)
		if err != nil {
			return err
		}
		return printJSON(pv)
	case "health":
		if err := c.Health(ctx); err != nil {
			return err
		}
		fmt.Println("ok")
		return nil
	case "trace":
		// omnisag-ctl trace <user> <group,group,...> <host> <port>
		if len(args) < 5 {
			return fmt.Errorf("usage: omnisag-ctl trace <user> <group,group> <host> <port>")
		}
		pv, err := c.GetPolicy(ctx)
		if err != nil {
			return err
		}
		port, err := strconv.Atoi(args[4])
		if err != nil {
			return fmt.Errorf("bad port %q", args[4])
		}
		groups := strings.Split(args[2], ",")
		ex := tui.Explain(pv, args[1], groups, args[3], port)
		for _, l := range ex.Lines {
			fmt.Println(l)
		}
		return nil
	case "tui":
		var opts tui.Options
		if len(args) >= 3 && args[1] == "-play" {
			cast, err := loadCast(args[2])
			if err != nil {
				return err
			}
			opts.Cast = cast
		}
		return tui.Run(ctx, c, opts)
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func loadCast(path string) (*tui.Cast, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	c, err := tui.ParseCast(f)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func usage() {
	fmt.Fprintln(os.Stderr, `omnisag-ctl [-api URL] [-token TOK] <command>
  sessions            list live sessions
  sessions kill <id>  terminate a session
  approvals           list approval requests
  approve <id>        approve a request (operator; four-eyes enforced)
  deny <id>           deny a request (operator)
  policy              show the compiled policy
  trace <u> <g,..> <host> <port>  explain why a user can/can't reach a target
  tui [-play <cast>]  interactive terminal UI (sessions/policy/approvals/replay)
  health              check the API`)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
