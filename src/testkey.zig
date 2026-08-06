//! `securearc-testkey`: does the ARC key in DNS match the key on disk.
//!
//! The tool itself is `securemilter.testkey`, shared with `securedkim-testkey`.
//! This file is the 18 lines the two copies actually differed in: a name, a
//! usage text, and the daemon to name when a key's permissions are wrong
//! (refactor plan stage 5.1).

const securemilter = @import("securemilter");
const securemilter_crypto = @import("securemilter_crypto");

const Usage =
    \\Usage: securearc-testkey [options]
    \\
    \\Fetch an ARC DNS key record and verify it matches a local private key.
    \\ARC uses the same selector._domainkey.domain DNS format as DKIM.
    \\
    \\Options:
    \\  -s <selector>    ARC selector name (required)
    \\  -d <domain>      Domain name (required)
    \\  -k <keyfile>     Private key file to compare against (required)
    \\  -n <nameserver>  DNS nameserver (default: 127.0.0.1)
    \\  -p <port>        DNS nameserver port (default: 53)
    \\  -h               Show this help
    \\
    \\Examples:
    \\  securearc-testkey -s arc2026 -d bambania.com -k /path/to/arc.key
    \\
;

const Tool = securemilter.testkey.Tool(securemilter_crypto, .{
    .name = "securearc-testkey",
    .daemon = "securearc",
    .usage = Usage,
});

pub const main = Tool.main;
