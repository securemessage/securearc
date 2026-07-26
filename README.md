# SecureARC

High-performance ARC (Authenticated Received Chain) milter implementing RFC 8617.

SecureARC validates ARC chains on inbound mail and seals messages with new ARC sets on relay/forwarding. It reuses DKIM canonicalization, signing, and verification primitives from `securemilter-lib`.

## Features

- **ARC chain validation**: Verify ARC-Message-Signature (AMS) and ARC-Seal (AS) headers
- **ARC sealing**: Construct new ARC set (AAR + AMS + AS) for forwarded messages
- **Multi-mode**: Separate verify/seal/both modes per listener
- **Thread-per-core**: kqueue-based event loop, SO_REUSEPORT, share-nothing workers
- **RSA-SHA256 + Ed25519-SHA256**: Dual algorithm support (RFC 8463)
- **ZMQ event publishing**: Fire-and-forget events for monitoring/reporting

## Building

```sh
zig build
```

## Configuration

See `config/securearc.conf.sample` for a complete example.

## Milter Chain Position

SecureARC should run AFTER SecureDKIM (needs DKIM results in Authentication-Results) and AFTER SecureDMARC (for complete AAR):

```
smtpd_milters = inet:8890, inet:8891, inet:8894, inet:8895
#               securespf  securedkim  securedmarc  securearc
```

For sealing on relay (outbound forwarding):
```
# Submission milter chain (port 587)
smtpd_milters = inet:8892, inet:8896
#               securedkim-sign  securearc-seal
```

## License

BSD-2-Clause. Copyright (c) 2026, Daniel Morante.
