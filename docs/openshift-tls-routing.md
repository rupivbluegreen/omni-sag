# SSH over TLS through an OpenShift passthrough Route

Omni-SAG's SSH data path can optionally be wrapped in TLS (`gatewayTLS.enabled: true` in the
Helm chart). This exists for one reason: SSH sends its version banner immediately on connect,
before any bytes an HTTP/SNI-aware router could use to pick a backend — a raw SSH listener is
invisible to that class of ingress. Wrapping the listener in TLS makes the client perform a TLS
handshake (carrying SNI) *before* SSH starts, so an OpenShift Route with
`spec.tls.termination: passthrough` can route purely off the ClientHello's server name, without
ever decrypting the connection — the same mechanism as Teleport's "TLS Routing."

The plain-SSH listener keeps serving unmodified alongside this — it's an additional path, not a
replacement.

## Enable it

```yaml
# values.yaml (or --set on the CLI)
gatewayTLS:
  enabled: true
  certSecretName: omni-sag-gateway-tls   # kubernetes.io/tls Secret: tls.crt, tls.key
  route:
    enabled: true
    host: gateway.apps.cluster.example.com
```

`certSecretName` must already exist in the release namespace — the chart never generates or
manages TLS material:

```console
$ kubectl create secret tls omni-sag-gateway-tls \
    --cert=gateway.crt --key=gateway.key -n <namespace>
```

## Connect

No custom client — plain OpenSSH, using `openssl s_client` as a `ProxyCommand` to perform the TLS
leg and hand the gateway the decrypted SSH byte stream:

```console
$ ssh -o ProxyCommand="openssl s_client -quiet -servername %h -connect %h:443" \
    'alice%db1.lab.local'@gateway.apps.cluster.example.com
```

`%h` is substituted by OpenSSH with the SSH destination host — here,
`gateway.apps.cluster.example.com`. It must be **exactly the Route's hostname**
(`gatewayTLS.route.host`, or whatever OpenShift assigned if you left `host` empty — check with
`oc get route <release>-ssh`): both the Route's SNI match and the server certificate's SAN are
keyed off that hostname. A different `%h` (an IP, or a hostname the Route doesn't recognize) gets
no match at the router and is dropped before it ever reaches the gateway.

`-connect %h:443` targets the OpenShift router's HTTPS port, not the gateway directly — the Route
terminates client TLS connections at the router (443), then forwards to the gateway's Service on
whatever internal port `spec.port.targetPort` names (`sshtls`). You never need to know or reach
that internal port yourself.

Everything past the `ProxyCommand` — AD+MFA auth, policy, `+pcode` role selection, tunnels,
evidence — is identical to plain SSH; TLS is purely a transport-layer disguise for the ingress hop.

## Mutual TLS (optional)

Set `gatewayTLS.clientCAEnabled: true` and add a `ca.crt` key to `certSecretName` to require a
client certificate on the TLS listener. `openssl s_client` takes `-cert`/`-key` for this:

```console
$ ssh -o ProxyCommand="openssl s_client -quiet -servername %h -connect %h:443 \
    -cert client.crt -key client.key" alice@gateway.apps.cluster.example.com
```

This gates the TLS handshake itself, before SSH auth ever runs — independent of, and in addition
to, the gateway's own AD+MFA authentication.

## Router timeouts

The OpenShift router's default idle timeout will still cut long-lived SSH sessions and `-L`
tunnels riding a passthrough Route unless raised. Set it via `gatewayTLS.route.annotations`:

```yaml
gatewayTLS:
  route:
    annotations:
      haproxy.router.openshift.io/timeout: "1h"
```
