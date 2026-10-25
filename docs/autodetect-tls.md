# clouds.yaml TLS settings during service autodetection

Design notes for the fix to upstream issue `openstack-exporter/openstack-exporter#639`.

## Problem

In single-cloud mode, the exporter autodetects services at startup by authenticating to Keystone.
That connection ignored the TLS settings in `clouds.yaml` (`cacert`, `cert`/`key`, `verify`),
so on clouds behind a private CA, or that require a client certificate, the exporter exited before collecting anything:

```text
Post "https://<keystone>/v3/auth/tokens": tls: failed to verify certificate: x509: certificate signed by unknown authority
```

The exporter never starts its HTTP server, so every OpenStack metric for that cloud is lost and alerts built on them go silent.
It's a regression for anyone upgrading from v1.x, which had no autodetection and whose collectors already honored `cacert`.
The workarounds are poor: `--disable-service-autodetect` enables every service, so each one the cloud doesn't run must be disabled by hand.
Adding the CA to the system trust store works only for a private CA, and `verify: false` didn't help, because autodetection ignored it too.

## Root cause

Two code paths built the HTTP transport, and only one applied the TLS settings:

* `NewExporter` built a transport from the cloud's TLS settings.
* `autodetectServices` passed `nil` to `AutodetectServicesFromCatalog`, which fell back to Go's default TLS settings.

## Design

### One transport builder for every client

`NewTransportForCloud` loads the cloud from `clouds.yaml`, and `transportFromCloudConfig` builds the transport from it.
Both `NewExporter` and `autodetectServices` use them, so both paths now apply the same settings.
The TLS configuration logic moved from `NewExporter` unchanged, apart from the `nil` `Verify` guard below.
A caller can still pass a `nil` transport to `AutodetectServicesFromCatalog`; follow-up 1 removes that possibility.

### A new transport per call

`AuthenticatedClientV2` sets `Proxy` on the transport it receives, so sharing one transport could race
when clients are built concurrently, for example in multi-cloud `/probe` requests.
Each call still builds its own transport, as before. With the change below, that assignment is redundant (follow-up 2).

### Start from the default transport

TLS transports are built from a clone of `http.DefaultTransport` instead of a bare `http.Transport`. This brings two fixes:

* **The proxy setting survives `OS_DEBUG`.** `OS_DEBUG` wraps the transport in a request logger, which stopped `AuthenticatedClientV2` from setting the proxy, so collectors ignored `HTTPS_PROXY`.
  Moving autodetection onto this transport would have spread that bug to startup.
* **Connections get Go's default dial, TLS handshake and idle-connection timeouts.** The bare transport had none,
  so a Keystone that never finished the handshake could hang the collectors, and with this change would also hang autodetection.

HTTP/2 stays off, as it was for the bare transport. Enabling it for every collector is a separate change.

### Guards for values real configuration can't produce

Two cases that real configuration can't produce fall back to the previous behavior instead of panicking or adding a new startup error:

* a `nil` `Verify` is treated as `true`
* if `http.DefaultTransport` has been replaced (`httpmock` does this in tests), the previous bare transport is used, plus the proxy

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| `AutodetectServicesFromCatalog` builds a transport when given `nil` | `nil` would quietly mean "load from config", and the function would need a logger parameter. |
| Build the transport inside `newAuthenticatedProviderClient` for every caller | Probably the right long-term design, but it touches every service client. Follow-up 1. |
| gophercloud/utils' `clientconfig.PrepareTLSConfig` | It replaces the system CA certificates instead of adding `cacert` to them, turns an unreadable CA into a startup error, and starts reading the `OS_CACERT`/`OS_CERT`/`OS_KEY`/`OS_INSECURE` environment variables. |
| Only add `Proxy` to the bare transport | Fixes the proxy, but leaves no timeouts. |
| Clone the default transport, HTTP/2 included | Turns HTTP/2 on for every collector, which is out of scope. |
| Drop the fallback, or return an error instead | Panics, or adds a new startup failure, when the default transport has been replaced. |

## Behavior changes

* Autodetection honors `cacert`, `cert`/`key`, `verify` and `OS_DEBUG` logging. Credentials are masked in the log.
* In single-cloud mode, a broken `cert` or `key` now fails at startup instead of when each exporter is created.
* Transports with TLS settings, for autodetection and collectors, use `HTTPS_PROXY` under `OS_DEBUG` and have timeouts.
  There is still no response header timeout, as in Go's default transport. HTTP/2 stays off.

## Follow-ups

1. Build the transport in one place (`newAuthenticatedProviderClient`), so no caller can miss it.
2. Remove the now-redundant `Proxy` assignment in `AuthenticatedClientV2`. Transports would then be safe to share,
   so multi-cloud `/probe`, which builds its clients on every request, could reuse connections.
3. Add a DevStack integration test with `tls-proxy` enabled, to cover what the fakes can't: version discovery and real certificate chains.
   It should run with `SSL_CERT_FILE` pointing at an unrelated bundle. DevStack adds its CA to the system trust store, which would hide the bug.
