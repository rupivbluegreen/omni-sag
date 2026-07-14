// Command omnictl is a thin CLI over the Omni-SAG control-plane SDK
// (internal/api.Client). It lists and terminates live sessions and reads the
// policy. The Bubble Tea TUI (Slice 9) is layered on the same SDK.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/rupivbluegreen/omni-sag/internal/api"
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
		fmt.Fprintln(os.Stderr, "omnictl:", err)
		os.Exit(1)
	}
}

func dispatch(ctx context.Context, c *api.Client, args []string) error {
	switch args[0] {
	case "sessions":
		if len(args) >= 2 && args[1] == "kill" {
			if len(args) < 3 {
				return fmt.Errorf("usage: omnictl sessions kill <id>")
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
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
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
	fmt.Fprintln(os.Stderr, `omnictl [-api URL] [-token TOK] <command>
  sessions            list live sessions
  sessions kill <id>  terminate a session
  policy              show the compiled policy
  health              check the API`)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
