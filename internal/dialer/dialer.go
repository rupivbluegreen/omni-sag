// Package dialer is the single outbound path to session targets.
//
// No other package may call net.Dial/net.Dialer for targets: this is the
// single-dialer invariant the network-authz model depends on. It must not
// import internal/api, so the data path never depends on the control plane.
package dialer
