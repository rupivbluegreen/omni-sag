package sessions

import "errors"

// ErrNotFound is returned when a session id is unknown.
var ErrNotFound = errors.New("sessions: not found")

// ErrNotTerminable is returned when a session cannot be terminated (no hook).
var ErrNotTerminable = errors.New("sessions: not terminable")
