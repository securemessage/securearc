# SecureARC

High-performance ARC (Authenticated Received Chain) milter for Postfix, implementing RFC 8617.

## Overview

SecureARC validates ARC chains on inbound mail and seals messages with new ARC sets on relay/forwarding paths. This preserves authentication results across forwarding hops, enabling downstream receivers to validate the original authentication state even when SPF/DKIM break due to forwarding.

## Features

- **ARC chain validation** -- verify ARC-Message-Signature (AMS) and ARC-Seal (AS)
- **ARC sealing** -- construct new ARC set (AAR + AMS + AS) for forwarded messages
- **RSA-SHA256 and Ed25519-SHA256** algorithm support
- **Multi-mode** -- separate verify/seal/both modes per listener
- **Thread-per-core architecture** with kqueue I/O multiplexing
- **DNS resolution** with per-worker TTL caching and proactive health monitoring
- **Multi-listener** support (TCP and Unix domain sockets)
- **ZMQ event publishing** for monitoring/reporting
- **SIGHUP reload** without dropping connections

## Quick Start

```sh
# Build
zig build

# Create directories (mailnull is the shared FreeBSD milter account other
# milters already run as -- no dedicated user needed)
mkdir -p /var/run/securearc /usr/local/etc/securearc

# Generate ARC key (uses same format as DKIM)
securedkim-genkey -s arc2026 -d example.com -o /usr/local/etc/securearc/arc.key
# (the record lands in /usr/local/etc/securearc/arc.dns -- paste or $INCLUDE it
#  into your zone at arc2026._domainkey.example.com)

# Verify key is published
securearc-testkey -s arc2026 -d example.com -k /usr/local/etc/securearc/arc.key

# Set permissions
chmod 0600 /usr/local/etc/securearc/arc.key
chown mailnull:mailnull /usr/local/etc/securearc/arc.key

# Write config. This example is for a host that both validates inbound
# chains and seals outbound ones for the same mail flow (a relay or
# forwarding hop) -- one listener in `Mode = both` covers it; see
# "Postfix Integration" below for the verify-only case (most single-server
# operators that don't relay mail elsewhere) and for when to use two
# separate listeners instead (DMARC enforcement with the ARC override).
cat > /usr/local/etc/securearc/securearc.conf << 'EOF'
[global]
AuthservID      = mail.example.com
User            = mailnull
PidFile         = /var/run/securearc/securearc.pid
DnsNameserver   = 127.0.0.1

[listener:relay]
Socket          = inet:8895@127.0.0.1
Mode            = both
SealDomain      = example.com
SealSelector    = arc2026
SealKeyFile     = /usr/local/etc/securearc/arc.key
EOF

# Install and start
cp zig-out/bin/securearc /usr/local/sbin/
cp zig-out/bin/securearc-testkey /usr/local/sbin/
securearc -c /usr/local/etc/securearc/securearc.conf
```

## Configuration Reference

### [global]

| Option | Default | Description |
|--------|---------|-------------|
| `AuthservID` | `localhost` | Authentication-Results header identifier |
| `LocalAuthMethods` | *(empty)* | Comma-separated methods this ADMD evaluates locally (e.g. `spf, dkim, dmarc`); only matching A-R headers are copied into the AAR and signed |
| `StripAuthResults` | `no` | Remove pre-existing Authentication-Results headers claiming our `AuthservID`; enable when this is the first or only milter in the chain (RFC 8601 §5) |
| `Mode` | `verify` | Default `[listener:name]` `Mode` (`seal`, `verify`, or `both`) for any listener that does not set its own |
| `WorkerThreads` | `0` (auto) | Worker thread count (0 = CPU count) |
| `MaxConnections` | `256` | Max simultaneous connections per worker |
| `PidFile` | `/var/run/securearc/securearc.pid` | PID file path |
| `Foreground` | `no` | Run in foreground (no daemonize) |
| `User` | *(none)* | Drop privileges to this user |
| `UMask` | *(inherited)* | File-creation mask (octal) for the PID file and any unix-domain listener |
| `Syslog` | `yes` | Enable syslog output |
| `SyslogFacility` | `mail` | Syslog facility |
| `LogLevel` | `info` | Log level: err, warn, info, debug |
| `DnsNameserver` | `127.0.0.1` | Comma-separated nameserver IPs |
| `DnsTimeout` | `5` | DNS timeout in seconds |
| `DnsRetries` | `2` | DNS retry count |
| `DnsCacheSize` | `1000` | Per-worker DNS cache max entries |
| `DnsNegativeTTL` | `60` | Negative cache TTL in seconds |
| `SignedHeaders` | `from:to:subject:date:message-id` | Headers for ARC-Message-Signature |
| `MaxBodyBytes` | `10M` | Largest message body buffered to hash; 0 disables the limit |
| `MaxHeaders` | `500` | Largest number of headers accumulated per message; 0 disables the limit |
| `MaxHeaderBytes` | `1M` | Largest total header size per message; 0 disables the limit |
| `MinimumKeyBits` | `1024` | Smallest RSA key size accepted on an ARC-Message-Signature or ARC-Seal (RFC 8301 floor) |
| `MaxKeyRecords` | `3` | Key records tried per selector before giving up (max 8) |
| `MaxEvaluationMs` | `20000` | Wall-clock ceiling for evaluating one message; 0 disables it |
| `On-DNSError` | `tempfail` | What a sealing listener does on transient DNS failure: `tempfail`, `skip-seal`, or `seal-fail` |
| `ZmqEndpoint` | *(disabled)* | ZMQ PUB endpoint |
| `ZmqTopic` | `arc` | ZMQ topic prefix |

### [listener:name]

| Option | Default | Description |
|--------|---------|-------------|
| `Socket` | -- | `inet:port@ip` or `unix:/path`. The IP must be numeric (no DNS). An unparseable value is a fatal startup error, never ignored. |
| `Mode` | `verify` | `seal`, `verify`, or `both`. Inherits `[global] Mode` if unset there too |
| `SealDomain` | *(none)* | Domain for ARC sealing (required for seal mode) |
| `SealSelector` | *(none)* | DNS selector for seal key (required for seal mode) |
| `SealKeyFile` | *(none)* | Private key file for sealing (required for seal mode) |

`On-DNSError` is daemon-wide and read only from `[global]`; setting it in a listener section is a configuration error.

## Postfix Integration

Where SecureARC belongs in the chain depends on whether SecureDMARC is
enforcing policy and consuming ARC's result:

**SecureDMARC in its default stamp-only mode**: SecureARC runs last, since
nothing downstream needs to see its result:

```ini
smtpd_milters = inet:127.0.0.1:8890,
                inet:127.0.0.1:8891,
                inet:127.0.0.1:8894,
                inet:127.0.0.1:8895
milter_connect_macros = j {daemon_name} v {client_addr}
milter_default_action = accept
```

Order: **SPF (8890) → DKIM (8891) → DMARC (8894) → ARC (8895)**

**SecureDMARC enforcing, with the ARC trusted-forwarder override enabled**
(`Enforcement` + `TrustedSealersFile` in securedmarc.conf), SecureARC's
*verify* step must run **before** SecureDMARC instead, so a validated
`arc=` result exists when SecureDMARC decides whether to reject:

```ini
smtpd_milters = inet:127.0.0.1:8890,
                inet:127.0.0.1:8891,
                inet:127.0.0.1:8895,
                inet:127.0.0.1:8894
milter_connect_macros = j {daemon_name} v {client_addr}
milter_default_action = accept
```

Order: **SPF (8890) → DKIM (8891) → ARC (8895, verify) → DMARC (8894, enforce)**

See [securedmarc's README](https://pacyworld.dev/securemessage/securedmarc#dmarc-enforcement)
for the enforcement/override configuration itself.

### Do you need to seal anything?

Everything above covers *validating* inbound chains. Sealing (extending the
chain with a new set of your own) is only useful if this host relays or
forwards mail on to some other domain after evaluating it. If every message
this host authenticates is delivered to a local mailbox and goes no further,
skip sealing: run a `verify`-only listener (as in the examples above, with no
`SealDomain`/`SealSelector`/`SealKeyFile`) and stop there.

### If you do seal: prefer one `Mode = both` listener over two

If this host both validates and, on the same mail flow, seals a new set (a
relay or forwarding hop), use a single listener in `Mode = both` rather than
separate `verify` and `seal` listeners:

```ini
[listener:relay]
Socket       = inet:8895@127.0.0.1
Mode         = both
SealDomain   = example.com
SealSelector = arc2026
SealKeyFile  = /usr/local/etc/securearc/arc.key
```

`Mode = both` validates the chain once and seals the new set from that same
validation, in a single pass. Two separate listeners validate the chain
**twice**, at two different moments in time: a DNS change or key rotation
between the two can produce a `verify` listener stamping `arc=pass` while
the `seal` listener, moments later, writes `cv=fail` into the new set for
the same message: a self-contradictory attestation from the same ADMD.
`Mode = both` makes that structurally impossible, and needs one listener
instead of two. Since `smtpd_milters` runs once per inbound SMTP
transaction regardless of what happens to the message afterwards, one
`Mode = both` listener wired into `smtpd_milters` is enough to seal outbound
copies of accepted mail; no second listener needed on the outbound path.

**Exception:** if SecureDMARC is enforcing with the trusted-forwarder
override (above), you cannot use `Mode = both` here: DMARC has to run
*between* the verify and seal steps, so they need to stay on separate
listeners positioned on either side of it:

```ini
[listener:verify-inbound]
Socket = inet:8895@127.0.0.1
Mode   = verify

[listener:seal-outbound]
Socket       = inet:8896@127.0.0.1
Mode         = seal
SealDomain   = example.com
SealSelector = arc2026
SealKeyFile  = /usr/local/etc/securearc/arc.key
```

Wire `verify-inbound` into `smtpd_milters` before SecureDMARC, and
`seal-outbound` into whichever Postfix service actually relays or forwards
the message onward, after SecureDMARC has run.

## CLI Tools

### securearc-testkey

Verify ARC DNS key record matches local private key:

```sh
securearc-testkey -s arc2026 -d example.com -k /usr/local/etc/securearc/arc.key
```

> **Note**: Use `securedkim-genkey` to generate ARC keys -- ARC uses the same `selector._domainkey.domain` DNS format as DKIM.

### securearc-check

Validate the ARC chain of a message file, calling the same chain-validation code path the daemon uses:

```sh
securearc-check message.eml
securearc-check -n 127.0.0.1 -p 5353 -v message.eml
```

### securearc-seal

Seal a message file, calling the same ARC-set construction the daemon uses; prints the new `ARC-Authentication-Results`, `ARC-Seal`, and `ARC-Message-Signature` fields:

```sh
securearc-seal -d example.com -s arc2026 -k /usr/local/etc/securearc/arc.key \
    --methods spf,dkim,dmarc message.eml
```

## Signals

- **SIGHUP** -- Reload configuration. The reloadable settings are adopted as one unit, so a message is always handled entirely under a single configuration. Covers the seal key, `AuthservID`, `SealDomain`, `SealSelector`, `SignedHeaders`, `LocalAuthMethods`, `StripAuthResults`, `MinimumKeyBits`, `On-DNSError` and the resolver settings. A failed reload leaves the previous configuration in place and logs why.
- **SIGTERM** -- Graceful shutdown (30s drain timeout)

Listen addresses, per-listener `Mode`, the `Max*` caps, the ZMQ endpoint and the process
settings are read at startup only and need a restart -- see `securearc(8)` SIGNALS for
the full list and the reason in each case.

## Part of the SecureMilter Suite

- [securemilter-lib](https://pacyworld.dev/securemessage/securemilter-lib) -- Shared infrastructure library
- [securemilter-crypto](https://pacyworld.dev/securemessage/securemilter-crypto) -- Cryptographic primitives
- [SecureSPF](https://pacyworld.dev/securemessage/securespf) -- SPF verification
- [SecureDKIM](https://pacyworld.dev/securemessage/securedkim) -- DKIM signing and verification
- [SecureDMARC](https://pacyworld.dev/securemessage/securedmarc) -- DMARC policy evaluation
- **SecureARC** -- ARC chain validation and sealing (this project)

## Requirements

- Zig 0.15.x
- FreeBSD (kqueue/kevent)
- OpenSSL (libcrypto) for RSA operations
- Postfix with milter support (`milter_protocol = 6`)

## License

BSD-2-Clause. Copyright (c) 2026, Daniel Morante.
