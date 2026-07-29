# SecureARC

High-performance ARC (Authenticated Received Chain) milter for Postfix, implementing RFC 8617.

## Overview

SecureARC validates ARC chains on inbound mail and seals messages with new ARC sets on relay/forwarding paths. This preserves authentication results across forwarding hops, enabling downstream receivers to validate the original authentication state even when SPF/DKIM break due to forwarding.

## Features

- **ARC chain validation** — verify ARC-Message-Signature (AMS) and ARC-Seal (AS)
- **ARC sealing** — construct new ARC set (AAR + AMS + AS) for forwarded messages
- **RSA-SHA256 and Ed25519-SHA256** algorithm support
- **Multi-mode** — separate verify/seal/both modes per listener
- **Thread-per-core architecture** with kqueue I/O multiplexing
- **DNS resolution** with per-worker TTL caching and proactive health monitoring
- **Multi-listener** support (TCP and Unix domain sockets)
- **ZMQ event publishing** for monitoring/reporting
- **SIGHUP reload** without dropping connections

## Quick Start

```sh
# Build
zig build

# Create user and directories
pw useradd _arc -d /nonexistent -s /usr/sbin/nologin
mkdir -p /var/run/securearc /usr/local/etc/securearc
chown _arc:_arc /var/run/securearc

# Generate ARC key (uses same format as DKIM)
securedkim-genkey -s arc2026 -d example.com -o /usr/local/etc/securearc/arc.key
# (add the DNS TXT record to your zone at arc2026._domainkey.example.com)

# Verify key is published
securearc-testkey -s arc2026 -d example.com -k /usr/local/etc/securearc/arc.key

# Set permissions
chmod 0600 /usr/local/etc/securearc/arc.key
chown _arc:_arc /usr/local/etc/securearc/arc.key

# Write config
cat > /usr/local/etc/securearc/securearc.conf << 'EOF'
[global]
AuthservID      = mail.example.com
User            = _arc
PidFile         = /var/run/securearc/securearc.pid
DnsNameserver   = 127.0.0.1

[listener:verify-inbound]
Socket          = inet:8895@0.0.0.0
Mode            = verify

[listener:seal-relay]
Socket          = inet:8896@0.0.0.0
Mode            = seal
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
| `WorkerThreads` | `0` (auto) | Worker thread count (0 = CPU count) |
| `PidFile` | `/var/run/securearc/securearc.pid` | PID file path |
| `Foreground` | `no` | Run in foreground (no daemonize) |
| `User` | *(none)* | Drop privileges to this user |
| `Syslog` | `yes` | Enable syslog output |
| `SyslogFacility` | `mail` | Syslog facility |
| `LogLevel` | `info` | Log level: err, warn, info, debug |
| `DnsNameserver` | `127.0.0.1` | Comma-separated nameserver IPs |
| `DnsTimeout` | `5` | DNS timeout in seconds |
| `DnsRetries` | `2` | DNS retry count |
| `DnsCacheSize` | `1000` | Per-worker DNS cache max entries |
| `DnsNegativeTTL` | `60` | Negative cache TTL in seconds |
| `SignedHeaders` | `from:to:subject:date:message-id` | Headers for ARC-Message-Signature |
| `ZmqEndpoint` | *(disabled)* | ZMQ PUB endpoint |
| `ZmqTopic` | `arc` | ZMQ topic prefix |

### [listener:name]

| Option | Default | Description |
|--------|---------|-------------|
| `Socket` | — | `inet:port@host` or `unix:/path` |
| `Mode` | `verify` | `seal`, `verify`, or `both` |
| `SealDomain` | *(none)* | Domain for ARC sealing (required for seal mode) |
| `SealSelector` | *(none)* | DNS selector for seal key (required for seal mode) |
| `SealKeyFile` | *(none)* | Private key file for sealing (required for seal mode) |

## Postfix Integration

SecureARC must be **last** in the inbound milter chain:

```ini
smtpd_milters = inet:127.0.0.1:8890,
                inet:127.0.0.1:8891,
                inet:127.0.0.1:8894,
                inet:127.0.0.1:8895
milter_connect_macros = j {daemon_name} v {client_addr}
milter_default_action = accept
```

Order: **SPF (8890) → DKIM (8891) → DMARC (8894) → ARC (8895)**

For relay/forwarding sealing (separate listener):

```ini
# In master.cf transport or relay service
-o smtp_milters=inet:127.0.0.1:8896
```

## CLI Tools

### securearc-testkey

Verify ARC DNS key record matches local private key:

```sh
securearc-testkey -s arc2026 -d example.com -k /usr/local/etc/securearc/arc.key
```

> **Note**: Use `securedkim-genkey` to generate ARC keys — ARC uses the same `selector._domainkey.domain` DNS format as DKIM.

## Signals

- **SIGHUP** — Reload configuration. The reloadable settings are adopted as one unit, so a message is always handled entirely under a single configuration. Covers the seal key, `AuthservID`, `SealDomain`, `SealSelector`, `SignedHeaders`, `LocalAuthMethods`, `StripAuthResults`, `MinimumKeyBits`, `On-DNSError` and the resolver settings. A failed reload leaves the previous configuration in place and logs why.
- **SIGTERM** — Graceful shutdown (30s drain timeout)

Listen addresses, per-listener `Mode`, the `Max*` caps, the ZMQ endpoint and the process
settings are read at startup only and need a restart — see `securearc(8)` SIGNALS for
the full list and the reason in each case.

## Part of the SecureMilter Suite

- [securemilter-lib](https://pacyworld.dev/securemessage/securemilter-lib) — Shared infrastructure library
- [securemilter-crypto](https://pacyworld.dev/securemessage/securemilter-crypto) — Cryptographic primitives
- [SecureSPF](https://pacyworld.dev/securemessage/securespf) — SPF verification
- [SecureDKIM](https://pacyworld.dev/securemessage/securedkim) — DKIM signing and verification
- [SecureDMARC](https://pacyworld.dev/securemessage/securedmarc) — DMARC policy evaluation
- **SecureARC** — ARC chain validation and sealing (this project)

## Requirements

- Zig 0.15.x
- FreeBSD (kqueue/kevent)
- OpenSSL (libcrypto) for RSA operations
- Postfix with milter support (`milter_protocol = 6`)

## License

BSD-2-Clause. Copyright (c) 2026, Daniel Morante.
