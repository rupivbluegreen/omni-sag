// Package policy resolves roles and evaluates access decisions.
//
// It must stay pure (inputs -> decision) and must not import
// internal/session, so the evaluator remains property-testable.
package policy
