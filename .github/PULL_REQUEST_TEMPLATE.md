<!-- Thanks for the PR! 🙌  Keep it focused; one logical change is easiest to review. -->

## What & why

What does this change, and why?

Closes # <!-- issue number, if any -->

## How I tested it

- [ ] `make ci` is green (build + gofmt + vet + import-rules + tests)
- [ ] Added/updated tests for the change
- [ ] Ran the relevant package under `-race` (if concurrency is involved)
- [ ] Tried it against the lab (`make lab-up`) — if applicable

## Security invariants (tick what applies / N/A)

- [ ] Doesn't add a `net.Dial` outside `internal/dialer`
- [ ] Any new error/dependency-failure path **fails closed**
- [ ] Doesn't make the data path import `internal/api`
- [ ] Doesn't swallow an evidence `Emit` error
- [ ] Doesn't put a secret into a Go `string` (in `internal/credential`)

## Anything reviewers should know

Trade-offs, follow-ups, screenshots, etc.
