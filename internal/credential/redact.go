package credential

import "bytes"

// Redact returns a copy of data with every occurrence of each secret's bytes
// replaced by '*' of equal length. It is the keystroke-suppression primitive:
// an injected credential must never be written into a session recording or
// transcript, so recorded input/output is passed through Redact first. The
// input slice is not modified.
func Redact(data []byte, secrets ...*Secret) []byte {
	out := append([]byte(nil), data...)
	for _, s := range secrets {
		b := s.Bytes()
		if len(b) == 0 {
			continue
		}
		out = bytes.ReplaceAll(out, b, bytes.Repeat([]byte("*"), len(b)))
	}
	return out
}
