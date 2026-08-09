//! SecureARC configuration: listener modes, DNS-failure policy, INI parser.
//! Pure parsing layer; testable without a running daemon.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const config_mod = securemilter.config;
const listener_mod = securemilter.listener;
const connection_mod = securemilter.connection;
const worker_mod = securemilter.worker;
const dns_mod = securemilter.dns;
const deadline_mod = securemilter.deadline;
const header_scrub = securemilter.header_scrub;

const securemilter_crypto = @import("securemilter_crypto");
const crypto = securemilter_crypto.crypto;

/// For `DEFAULT_MAX_KEY_RECORDS` only, so the default an operator gets and the
/// ceiling the verifier enforces are declared in one place rather than drifting.
const chain = @import("chain.zig");

pub const Mode = enum {
    verify_only,
    seal_only,
    both,
};

/// Parse `Mode` from config. Unrecognised values are errors (previously silent:
/// a typo like `Mode=sealing` ran seal in verify mode without warning).
pub fn parseMode(raw: []const u8) error{InvalidMode}!Mode {
    if (mem.eql(u8, raw, "verify")) return .verify_only;
    if (mem.eql(u8, raw, "seal")) return .seal_only;
    if (mem.eql(u8, raw, "both")) return .both;
    return error.InvalidMode;
}

/// Log-facing mode label (matches accepted `Mode=` values).
pub fn modeLabel(m: Mode) []const u8 {
    return switch (m) {
        .verify_only => "verify",
        .seal_only => "seal",
        .both => "both",
    };
}

/// What to do when DNS fails during sealing (audit A-12).
/// RFC 8617 §5.1.2 makes `cv=fail` permanent, so sealing a DNS failure into
/// the chain is irreversible harm to a third party. Default chosen by least
/// total impact (same rationale as OpenDKIM's `On-DNSError`).
pub const OnDnsError = enum {
    /// Defer (4xx), let sender retry. Only non-destructive answer for a
    /// message-modifying hop.
    tempfail,
    /// Pass through without sealing, report `arc=temperror`. Right for relays
    /// that do not modify the message.
    skip_seal,
    /// Seal `cv=fail`. Pre-A-12 behaviour, kept for operators who depended on it.
    /// Not recommended: inflicts permanent harm on a potentially good chain.
    seal_fail,
};

/// Parse `On-DNSError`; rejects unrecognised values (silent default would pick
/// an unintended policy on the transient-fault path).
pub fn parseOnDnsError(raw: []const u8) error{InvalidOnDnsError}!OnDnsError {
    if (mem.eql(u8, raw, "tempfail")) return .tempfail;
    if (mem.eql(u8, raw, "skip-seal")) return .skip_seal;
    if (mem.eql(u8, raw, "seal-fail")) return .seal_fail;
    return error.InvalidOnDnsError;
}

/// SecureARC runtime configuration.
pub const ArcConfig = struct {
    authserv_id: []const u8,
    listen_addresses: []const listener_mod.ListenAddress,
    worker_threads: u32,
    /// Per-worker connection cap (audit L-2). No default: previously hard-coded
    /// while `MaxConnections` was honoured by only one daemon.
    max_connections: u32,
    pid_file: []const u8,
    foreground: bool,
    user: ?[]const u8,
    /// File-creation mask for the PID file and any unix-domain listener.
    umask: ?std.posix.mode_t,
    dns_nameservers: []const []const u8,
    dns_timeout_ms: u32,
    dns_retries: u8,
    dns_cache_size: u32,
    dns_negative_ttl: u32,
    /// Mode per listener, index-parallel to `listen_addresses` (audit A-2).
    /// One entry per socket: a host with verify + seal listeners must have each
    /// behave as configured.
    modes: []const Mode,
    seal_domain: ?[]const u8,
    seal_selector: ?[]const u8,
    seal_key_file: ?[]const u8,
    signed_headers: []const u8,
    local_auth_methods: []const []const u8,
    strip_auth_results: bool,
    zmq_endpoint: ?[]const u8,
    zmq_topic: []const u8,
    limits: connection_mod.Limits,
    min_key_bits: crypto.MinRsaBits,
    max_key_records: u8,
    max_evaluation_ms: i64,
    on_dns_error: OnDnsError,
};
pub fn parseArcConfig(allocator: Allocator, cfg: *const config_mod.Config) !ArcConfig {
    const global = cfg.getSection("global") orelse return error.MissingGlobalSection;

    const authserv_id = global.get("AuthservID") orelse "localhost";
    const workers = global.getInt("WorkerThreads", u32, 0);

    // Read beside `WorkerThreads` because the two are multiplied: `calculateFdNeed`
    // sizes the RLIMIT_NOFILE raise as workers x (max_connections + listeners + 3),
    // so raising either one alone is not the whole change.
    const max_connections = global.getInt("MaxConnections", u32, worker_mod.DEFAULT_MAX_CONNECTIONS);

    const pid_file = global.getOrDefault("PidFile", "/var/run/securearc/securearc.pid");
    const foreground_val = global.getBool("Foreground", false);
    const user = global.get("User");
    const umask = try global.getMode("UMask");

    // What a sealing listener does when DNS fails transiently (audit A-12).
    // Validated here, before anything is allocated, so a typo costs nothing to
    // unwind.
    const on_dns_error = try parseOnDnsError(global.getOrDefault("On-DNSError", "tempfail"));

    var addrs: std.ArrayListUnmanaged(listener_mod.ListenAddress) = .{};
    errdefer addrs.deinit(allocator);
    var modes: std.ArrayListUnmanaged(Mode) = .{};
    errdefer modes.deinit(allocator);

    // A `[global] Mode` supplies the default for any listener that does not
    // name one, so single-socket configs keep working unchanged.
    const default_mode: Mode = if (global.get("Mode")) |raw|
        try parseMode(raw)
    else
        .verify_only;

    var seal_domain: ?[]const u8 = null;
    var seal_selector: ?[]const u8 = null;
    var seal_key_file: ?[]const u8 = null;

    for (cfg.section_order.items) |section_name| {
        if (mem.startsWith(u8, section_name, "listener:")) {
            const section = cfg.getSection(section_name) orelse continue;

            // X-14: a malformed or missing Socket is refused, not skipped.
            const addr = try listener_mod.parseListenerSocket(section_name, section.get("Socket"));
            try addrs.append(allocator, addr);

            // Appended in lockstep with `addrs`, so the index the worker hands
            // back on a connection selects this listener's own mode.
            const listener_mode: Mode = if (section.get("Mode")) |raw|
                try parseMode(raw)
            else
                default_mode;
            try modes.append(allocator, listener_mode);

            // Refuse a policy we would otherwise ignore. `On-DNSError` is
            // daemon-wide and read from [global]; accepted-but-ignored here it
            // would silently apply the default instead of what the operator
            // asked for — the same silent fallback as A-2, on the one option
            // whose purpose is to stop a transient fault becoming permanent.
            if (section.get("On-DNSError") != null) return error.OnDnsErrorNotPerListener;

            seal_domain = section.get("SealDomain") orelse seal_domain;
            seal_selector = section.get("SealSelector") orelse seal_selector;
            seal_key_file = section.get("SealKeyFile") orelse seal_key_file;
        }
    }

    // Loopback, NOT 0.0.0.0. The milter protocol has no authentication of any
    // kind, so whoever reaches this socket is trusted completely: on a verify
    // listener they dictate the Authentication-Results this host will stamp, which
    // is finding X-1/M-1 handed over directly, and on a seal listener they get an
    // unauthenticated signing oracle for the sealing domain. Postfix is the only
    // thing that should ever connect, and it is local.
    //
    // Binding wide has to be a decision the operator writes down, not what happens
    // when they write nothing. A-2 was re-rated High for exactly this class of
    // mistake -- a securedkim instance had its public inbound socket in sign mode.
    if (addrs.items.len == 0) {
        try addrs.append(allocator, .{ .tcp = .{ .host = "127.0.0.1", .port = 8895 } });
        try modes.append(allocator, default_mode);
    }

    std.debug.assert(addrs.items.len == modes.items.len);

    // Seal identity remains daemon-wide. A `SealDomain`/`SealSelector`/
    // `SealKeyFile` in a listener section is still read, but it is applied to
    // every sealing socket, not just that one — the seal key is a single RCU
    // cell and giving each listener its own identity means N keys, N reload
    // paths and N floors to enforce. That is a feature (multi-tenant sealing),
    // not part of A-2, and is tracked as such; the collapse is recorded here
    // rather than left for the next reader to discover.
    seal_domain = seal_domain orelse global.get("SealDomain");
    seal_selector = seal_selector orelse global.get("SealSelector");
    seal_key_file = seal_key_file orelse global.get("SealKeyFile");

    // Owned slice, borrowed contents. It needs unwinding of its own: everything
    // above is still an ArrayList with an errdefer, but this slice is not.
    // Without this, any `try` added below silently leaks it — which is exactly
    // what the On-DNSError validation did until it was moved to the top.
    const dns_nameservers = try global.getCsvList(allocator, "DnsNameserver", "127.0.0.1");
    errdefer allocator.free(dns_nameservers);
    const dns_timeout = global.getInt("DnsTimeout", u32, 5) * 1000;
    const dns_retries = global.getInt("DnsRetries", u8, 2);
    const dns_cache_size = global.getInt("DnsCacheSize", u32, 1000);
    const dns_negative_ttl = global.getInt("DnsNegativeTTL", u32, 60);
    const signed_headers = global.getOrDefault("SignedHeaders", "from:to:subject:date:message-id");

    // Authentication methods this ADMD actually evaluates, i.e. the results
    // other SecureMilter daemons on this host contribute to the chain. Only
    // these may be copied into an ARC-Authentication-Results header and sealed.
    // Empty by default: a host that runs nothing but the sealer has performed
    // no authentication, so its AAR must say so rather than repeat whatever the
    // sender wrote (RFC 8617 §5.1.1).
    const local_auth_methods = try global.getCsvList(allocator, "LocalAuthMethods", "");
    errdefer allocator.free(local_auth_methods);

    // Trust boundary: remove every A-R header claiming our authserv-id, not
    // just the arc= results this daemon replaces (RFC 8601 §5).
    const strip_auth_results = global.getBool("StripAuthResults", false);

    // Caps on attacker-controlled message content (audit X-4).
    const limits = connection_mod.Limits.fromSection(global);

    // Smallest RSA key accepted on an AMS or ARC-Seal (audit C-3). ARC inherits
    // DKIM's cryptography, so RFC 8301's floor applies to sealed hops too.
    const min_key_bits = crypto.resolveMinRsaBits(
        global.getInt(crypto.MIN_KEY_BITS_OPTION, u32, crypto.RFC8301_MIN_RSA_BITS),
    );

    // A rotation legitimately publishes two key records at one selector and RRset
    // order is unspecified, so committing to the first made the verdict depend on
    // which half DNS listed first (audit A-24; D-20 is the same defect in
    // `securedkim`). Same option name and default as that daemon deliberately --
    // in ARC the cost of getting it wrong is a `cv=fail`, which is permanent and
    // is honoured by every downstream hop.
    const max_key_records = global.getInt("MaxKeyRecords", u8, chain.DEFAULT_MAX_KEY_RECORDS);

    // X-21: the wall-clock bound on one chain validation, shared spelling and
    // default with `securespf`. The MaxKeyRecords cap bounds the work of one
    // selector; this bounds the time of the whole walk.
    const max_evaluation_ms = global.getInt(deadline_mod.OPTION_NAME, i64, deadline_mod.DEFAULT_MS);

    const zmq_endpoint = global.get("ZmqEndpoint");
    const zmq_topic = global.getOrDefault("ZmqTopic", "arc");

    return .{
        .authserv_id = authserv_id,
        .listen_addresses = try addrs.toOwnedSlice(allocator),
        .worker_threads = workers,
        .max_connections = max_connections,
        .pid_file = pid_file,
        .foreground = foreground_val,
        .user = user,
        .umask = umask,
        .dns_nameservers = dns_nameservers,
        .dns_timeout_ms = dns_timeout,
        .dns_retries = dns_retries,
        .dns_cache_size = dns_cache_size,
        .dns_negative_ttl = dns_negative_ttl,
        .modes = try modes.toOwnedSlice(allocator),
        .seal_domain = seal_domain,
        .seal_selector = seal_selector,
        .seal_key_file = seal_key_file,
        .signed_headers = signed_headers,
        .local_auth_methods = local_auth_methods,
        .strip_auth_results = strip_auth_results,
        .zmq_endpoint = zmq_endpoint,
        .zmq_topic = zmq_topic,
        .limits = limits,
        .min_key_bits = min_key_bits,
        .max_key_records = max_key_records,
        .max_evaluation_ms = max_evaluation_ms,
        .on_dns_error = on_dns_error,
    };
}

/// Duplicate a list of strings, list and contents both.
fn dupeList(allocator: Allocator, src: []const []const u8) ![]const []const u8 {
    const out = try allocator.alloc([]const u8, src.len);
    var made: usize = 0;
    errdefer {
        for (out[0..made]) |s| allocator.free(s);
        allocator.free(out);
    }
    for (src, 0..) |s, i| {
        out[i] = try allocator.dupe(u8, s);
        made = i + 1;
    }
    return out;
}

fn freeList(allocator: Allocator, list: []const []const u8) void {
    for (list) |s| allocator.free(s);
    allocator.free(list);
}

/// Configuration that can change without restarting the daemon.
///
/// An `Rcu` publishes one snapshot per message. Workers report quiescence only
/// between event-loop iterations, keeping that snapshot valid for the message.
///
/// All strings are owned because `reloadConfig` frees the source `Config`.
/// Listener addresses, modes, limits, and process settings remain restart-only.
pub const Reloadable = struct {
    authserv_id: []const u8,
    dns_config: dns_mod.ResolverConfig,
    seal_domain: ?[]const u8,
    seal_selector: ?[]const u8,
    signed_headers: []const u8,
    local_auth_methods: []const []const u8,
    min_key_bits: u32,
    max_key_records: u8,
    max_evaluation_ms: i64,
    on_dns_error: OnDnsError,
    strip_all: bool,

    /// Take an owning copy of the reloadable subset of `c`.
    pub fn init(allocator: Allocator, c: ArcConfig) !Reloadable {
        const authserv_id = try allocator.dupe(u8, c.authserv_id);
        errdefer allocator.free(authserv_id);

        const signed_headers = try allocator.dupe(u8, c.signed_headers);
        errdefer allocator.free(signed_headers);

        const seal_domain = if (c.seal_domain) |d| try allocator.dupe(u8, d) else null;
        errdefer if (seal_domain) |d| allocator.free(d);

        const seal_selector = if (c.seal_selector) |s| try allocator.dupe(u8, s) else null;
        errdefer if (seal_selector) |s| allocator.free(s);

        const methods = try dupeList(allocator, c.local_auth_methods);
        errdefer freeList(allocator, methods);

        const nameservers = try dupeList(allocator, c.dns_nameservers);
        errdefer freeList(allocator, nameservers);

        return .{
            .authserv_id = authserv_id,
            .dns_config = .{
                .nameservers = nameservers,
                .timeout_ms = c.dns_timeout_ms,
                .retries = c.dns_retries,
                .cache_size = c.dns_cache_size,
                .negative_ttl = c.dns_negative_ttl,
            },
            .seal_domain = seal_domain,
            .seal_selector = seal_selector,
            .signed_headers = signed_headers,
            .local_auth_methods = methods,
            .min_key_bits = c.min_key_bits.bits,
            .max_key_records = c.max_key_records,
            .max_evaluation_ms = c.max_evaluation_ms,
            .on_dns_error = c.on_dns_error,
            .strip_all = c.strip_auth_results,
        };
    }

    pub fn deinit(self: *Reloadable, allocator: Allocator) void {
        allocator.free(self.authserv_id);
        allocator.free(self.signed_headers);
        if (self.seal_domain) |d| allocator.free(d);
        if (self.seal_selector) |s| allocator.free(s);
        freeList(allocator, self.local_auth_methods);
        freeList(allocator, self.dns_config.nameservers);
    }

    /// Strip rule for Authentication-Results headers in this snapshot.
    ///
    /// This daemon always asserts the `arc` method.
    pub fn stripPolicy(self: *const Reloadable) header_scrub.StripPolicy {
        return .{ .own_methods = &.{"arc"}, .strip_all = self.strip_all };
    }
};

test "parse config minimal" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:verify]
        \\Socket = inet:8895@0.0.0.0
        \\Mode = verify
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    const arc_cfg = try parseArcConfig(std.testing.allocator, &cfg);
    defer std.testing.allocator.free(arc_cfg.listen_addresses);
    defer std.testing.allocator.free(arc_cfg.modes);
    defer std.testing.allocator.free(arc_cfg.dns_nameservers);
    defer std.testing.allocator.free(arc_cfg.local_auth_methods);

    try std.testing.expectEqualStrings("mail.test.com", arc_cfg.authserv_id);
    try std.testing.expectEqual(@as(usize, 1), arc_cfg.listen_addresses.len);
    try std.testing.expectEqual(@as(usize, 1), arc_cfg.modes.len);
    try std.testing.expectEqual(Mode.verify_only, arc_cfg.modes[0]);
}

// L-2 regression: `MaxConnections` controls both the accept cap and the
// `RLIMIT_NOFILE` calculation.
test "L-2: MaxConnections is honoured, and defaults when absent" {
    {
        var cfg = try config_mod.parse(std.testing.allocator,
            \\[global]
            \\AuthservID = mail.test.com
            \\MaxConnections = 32
        );
        defer cfg.deinit();

        const arc_cfg = try parseArcConfig(std.testing.allocator, &cfg);
        defer std.testing.allocator.free(arc_cfg.listen_addresses);
        defer std.testing.allocator.free(arc_cfg.modes);
        defer std.testing.allocator.free(arc_cfg.dns_nameservers);
        defer std.testing.allocator.free(arc_cfg.local_auth_methods);

        try std.testing.expectEqual(@as(u32, 32), arc_cfg.max_connections);
    }

    {
        var cfg = try config_mod.parse(std.testing.allocator,
            \\[global]
            \\AuthservID = mail.test.com
        );
        defer cfg.deinit();

        const arc_cfg = try parseArcConfig(std.testing.allocator, &cfg);
        defer std.testing.allocator.free(arc_cfg.listen_addresses);
        defer std.testing.allocator.free(arc_cfg.modes);
        defer std.testing.allocator.free(arc_cfg.dns_nameservers);
        defer std.testing.allocator.free(arc_cfg.local_auth_methods);

        try std.testing.expectEqual(worker_mod.DEFAULT_MAX_CONNECTIONS, arc_cfg.max_connections);
    }
}

// X-14. A malformed Socket must be refused rather than skipped, and must not
// fall through to the loopback default below.
test "a malformed listener Socket is refused, not replaced by the default" {
    var cfg = try config_mod.parse(std.testing.allocator,
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:typo]
        \\Socket = inet6:8895@::1
    );
    defer cfg.deinit();

    try std.testing.expectError(error.InvalidListenerSocket, parseArcConfig(std.testing.allocator, &cfg));
}

test "a hostname in Socket is refused at config time" {
    var cfg = try config_mod.parse(std.testing.allocator,
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:main]
        \\Socket = inet:8895@localhost
    );
    defer cfg.deinit();

    try std.testing.expectError(error.InvalidListenerSocket, parseArcConfig(std.testing.allocator, &cfg));
}

test "a listener section with no Socket is refused" {
    var cfg = try config_mod.parse(std.testing.allocator,
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:empty]
        \\Mode = verify
    );
    defer cfg.deinit();

    try std.testing.expectError(error.MissingListenerSocket, parseArcConfig(std.testing.allocator, &cfg));
}

// A malformed verify listener must not fall back to a sealing listener.
test "a typo cannot silently invert a verify listener into a sealing one" {
    var cfg = try config_mod.parse(std.testing.allocator,
        \\[global]
        \\AuthservID = mail.test.com
        \\Mode = seal
        \\
        \\[listener:verify]
        \\Socket = inet6:8895@::1
        \\Mode = verify
    );
    defer cfg.deinit();

    try std.testing.expectError(error.InvalidListenerSocket, parseArcConfig(std.testing.allocator, &cfg));
}

// The implicit milter listener is loopback-only because the protocol does not
// authenticate its clients.
test "the implicit listener binds loopback, not every interface" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    const arc_cfg = try parseArcConfig(std.testing.allocator, &cfg);
    defer std.testing.allocator.free(arc_cfg.listen_addresses);
    defer std.testing.allocator.free(arc_cfg.modes);
    defer std.testing.allocator.free(arc_cfg.dns_nameservers);
    defer std.testing.allocator.free(arc_cfg.local_auth_methods);

    try std.testing.expectEqual(@as(usize, 1), arc_cfg.listen_addresses.len);
    switch (arc_cfg.listen_addresses[0]) {
        .tcp => |tcp| {
            try std.testing.expectEqualStrings("127.0.0.1", tcp.host);
            try std.testing.expectEqual(@as(u16, 8895), tcp.port);
        },
        else => return error.TestUnexpectedResult,
    }
}

// An explicit routable listener remains supported for separate Postfix jails.
test "an explicit 0.0.0.0 socket is still honoured" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:wide]
        \\Socket = inet:8895@0.0.0.0
        \\Mode = verify
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    const arc_cfg = try parseArcConfig(std.testing.allocator, &cfg);
    defer std.testing.allocator.free(arc_cfg.listen_addresses);
    defer std.testing.allocator.free(arc_cfg.modes);
    defer std.testing.allocator.free(arc_cfg.dns_nameservers);
    defer std.testing.allocator.free(arc_cfg.local_auth_methods);

    switch (arc_cfg.listen_addresses[0]) {
        .tcp => |tcp| try std.testing.expectEqualStrings("0.0.0.0", tcp.host),
        else => return error.TestUnexpectedResult,
    }
}

test "local auth methods default to none" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    const arc_cfg = try parseArcConfig(std.testing.allocator, &cfg);
    defer std.testing.allocator.free(arc_cfg.listen_addresses);
    defer std.testing.allocator.free(arc_cfg.modes);
    defer std.testing.allocator.free(arc_cfg.dns_nameservers);
    defer std.testing.allocator.free(arc_cfg.local_auth_methods);

    // A sealer with no local authentication results emits none.
    try std.testing.expectEqual(@as(usize, 0), arc_cfg.local_auth_methods.len);
    try std.testing.expect(!arc_cfg.strip_auth_results);
}

test "local auth methods parse as a comma separated list" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
        \\LocalAuthMethods = spf, dkim ,dmarc
        \\StripAuthResults = yes
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    const arc_cfg = try parseArcConfig(std.testing.allocator, &cfg);
    defer std.testing.allocator.free(arc_cfg.listen_addresses);
    defer std.testing.allocator.free(arc_cfg.modes);
    defer std.testing.allocator.free(arc_cfg.dns_nameservers);
    defer std.testing.allocator.free(arc_cfg.local_auth_methods);

    try std.testing.expectEqual(@as(usize, 3), arc_cfg.local_auth_methods.len);
    try std.testing.expectEqualStrings("spf", arc_cfg.local_auth_methods[0]);
    try std.testing.expectEqualStrings("dkim", arc_cfg.local_auth_methods[1]);
    try std.testing.expectEqualStrings("dmarc", arc_cfg.local_auth_methods[2]);
    try std.testing.expect(arc_cfg.strip_auth_results);
}

test "parse config seal mode" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
        \\SealDomain = test.com
        \\SealSelector = arc2026
        \\
        \\[listener:seal]
        \\Socket = inet:8896@0.0.0.0
        \\Mode = seal
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    const arc_cfg = try parseArcConfig(std.testing.allocator, &cfg);
    defer std.testing.allocator.free(arc_cfg.listen_addresses);
    defer std.testing.allocator.free(arc_cfg.modes);
    defer std.testing.allocator.free(arc_cfg.dns_nameservers);
    defer std.testing.allocator.free(arc_cfg.local_auth_methods);

    try std.testing.expectEqual(Mode.seal_only, arc_cfg.modes[0]);
    try std.testing.expectEqualStrings("test.com", arc_cfg.seal_domain.?);
    try std.testing.expectEqualStrings("arc2026", arc_cfg.seal_selector.?);
}

// A-2 regression: listener modes must not overwrite each other.
test "each listener keeps its own mode" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
        \\SealDomain = test.com
        \\SealSelector = arc2026
        \\
        \\[listener:verify]
        \\Socket = inet:8895@0.0.0.0
        \\Mode = verify
        \\
        \\[listener:seal]
        \\Socket = inet:8896@0.0.0.0
        \\Mode = seal
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    const arc_cfg = try parseArcConfig(std.testing.allocator, &cfg);
    defer std.testing.allocator.free(arc_cfg.listen_addresses);
    defer std.testing.allocator.free(arc_cfg.modes);
    defer std.testing.allocator.free(arc_cfg.dns_nameservers);
    defer std.testing.allocator.free(arc_cfg.local_auth_methods);

    try std.testing.expectEqual(@as(usize, 2), arc_cfg.listen_addresses.len);
    try std.testing.expectEqual(arc_cfg.listen_addresses.len, arc_cfg.modes.len);
    try std.testing.expectEqual(Mode.verify_only, arc_cfg.modes[0]);
    try std.testing.expectEqual(Mode.seal_only, arc_cfg.modes[1]);
}

// Listener indices follow declaration order, which is also bind order.
test "listener modes follow declaration order" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:a]
        \\Socket = inet:8896@0.0.0.0
        \\Mode = seal
        \\
        \\[listener:b]
        \\Socket = inet:8895@0.0.0.0
        \\Mode = verify
        \\
        \\[listener:c]
        \\Socket = inet:8897@0.0.0.0
        \\Mode = both
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    const arc_cfg = try parseArcConfig(std.testing.allocator, &cfg);
    defer std.testing.allocator.free(arc_cfg.listen_addresses);
    defer std.testing.allocator.free(arc_cfg.modes);
    defer std.testing.allocator.free(arc_cfg.dns_nameservers);
    defer std.testing.allocator.free(arc_cfg.local_auth_methods);

    try std.testing.expectEqual(@as(usize, 3), arc_cfg.modes.len);
    try std.testing.expectEqual(Mode.seal_only, arc_cfg.modes[0]);
    try std.testing.expectEqual(Mode.verify_only, arc_cfg.modes[1]);
    try std.testing.expectEqual(Mode.both, arc_cfg.modes[2]);
}

test "a listener without Mode inherits the global default" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
        \\Mode = both
        \\
        \\[listener:inherits]
        \\Socket = inet:8895@0.0.0.0
        \\
        \\[listener:overrides]
        \\Socket = inet:8896@0.0.0.0
        \\Mode = verify
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    const arc_cfg = try parseArcConfig(std.testing.allocator, &cfg);
    defer std.testing.allocator.free(arc_cfg.listen_addresses);
    defer std.testing.allocator.free(arc_cfg.modes);
    defer std.testing.allocator.free(arc_cfg.dns_nameservers);
    defer std.testing.allocator.free(arc_cfg.local_auth_methods);

    try std.testing.expectEqual(Mode.both, arc_cfg.modes[0]);
    try std.testing.expectEqual(Mode.verify_only, arc_cfg.modes[1]);
}

// The implicit listener also needs an index-parallel mode entry.
test "implicit default listener gets a mode" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    const arc_cfg = try parseArcConfig(std.testing.allocator, &cfg);
    defer std.testing.allocator.free(arc_cfg.listen_addresses);
    defer std.testing.allocator.free(arc_cfg.modes);
    defer std.testing.allocator.free(arc_cfg.dns_nameservers);
    defer std.testing.allocator.free(arc_cfg.local_auth_methods);

    try std.testing.expectEqual(@as(usize, 1), arc_cfg.listen_addresses.len);
    try std.testing.expectEqual(@as(usize, 1), arc_cfg.modes.len);
    try std.testing.expectEqual(Mode.verify_only, arc_cfg.modes[0]);
}

// --- A-12: On-DNSError ------------------------------------------------------

test "On-DNSError accepts the three policies and refuses anything else" {
    try std.testing.expectEqual(OnDnsError.tempfail, try parseOnDnsError("tempfail"));
    try std.testing.expectEqual(OnDnsError.skip_seal, try parseOnDnsError("skip-seal"));
    try std.testing.expectEqual(OnDnsError.seal_fail, try parseOnDnsError("seal-fail"));

    // Enum tags are not accepted configuration values.
    try std.testing.expectError(error.InvalidOnDnsError, parseOnDnsError("skip_seal"));
    try std.testing.expectError(error.InvalidOnDnsError, parseOnDnsError("Tempfail"));
    try std.testing.expectError(error.InvalidOnDnsError, parseOnDnsError("defer"));
    try std.testing.expectError(error.InvalidOnDnsError, parseOnDnsError(""));
}

// `tempfail` avoids sealing a permanent failure after a transient DNS error.
test "On-DNSError defaults to tempfail and is read from the config" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    const arc_cfg = try parseArcConfig(std.testing.allocator, &cfg);
    defer std.testing.allocator.free(arc_cfg.listen_addresses);
    defer std.testing.allocator.free(arc_cfg.modes);
    defer std.testing.allocator.free(arc_cfg.dns_nameservers);
    defer std.testing.allocator.free(arc_cfg.local_auth_methods);

    try std.testing.expectEqual(OnDnsError.tempfail, arc_cfg.on_dns_error);

    const explicit_text =
        \\[global]
        \\AuthservID = mail.test.com
        \\On-DNSError = skip-seal
    ;

    var cfg2 = try config_mod.parse(std.testing.allocator, explicit_text);
    defer cfg2.deinit();

    const cfg2_parsed = try parseArcConfig(std.testing.allocator, &cfg2);
    defer std.testing.allocator.free(cfg2_parsed.listen_addresses);
    defer std.testing.allocator.free(cfg2_parsed.modes);
    defer std.testing.allocator.free(cfg2_parsed.dns_nameservers);
    defer std.testing.allocator.free(cfg2_parsed.local_auth_methods);

    try std.testing.expectEqual(OnDnsError.skip_seal, cfg2_parsed.on_dns_error);
}

// Reject a listener-level policy instead of silently using the global default.
test "On-DNSError in a listener section is refused rather than ignored" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:seal]
        \\Socket = inet:8895@0.0.0.0
        \\Mode = seal
        \\On-DNSError = seal-fail
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    try std.testing.expectError(
        error.OnDnsErrorNotPerListener,
        parseArcConfig(std.testing.allocator, &cfg),
    );
}

test "a bad On-DNSError value stops the daemon rather than picking a policy" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
        \\On-DNSError = ignore
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    try std.testing.expectError(error.InvalidOnDnsError, parseArcConfig(std.testing.allocator, &cfg));
}

test "an unrecognised Mode is refused" {
    try std.testing.expectEqual(Mode.verify_only, try parseMode("verify"));
    try std.testing.expectEqual(Mode.seal_only, try parseMode("seal"));
    try std.testing.expectEqual(Mode.both, try parseMode("both"));

    try std.testing.expectError(error.InvalidMode, parseMode("sealing"));
    try std.testing.expectError(error.InvalidMode, parseMode("Verify"));
    try std.testing.expectError(error.InvalidMode, parseMode(""));

    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:typo]
        \\Socket = inet:8895@0.0.0.0
        \\Mode = sealing
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    try std.testing.expectError(error.InvalidMode, parseArcConfig(std.testing.allocator, &cfg));
}

// --- Reloadable snapshot tests (audit A-14) ------------------------------------

/// An `ArcConfig` backed by mutable strings for ownership tests.
fn scratchConfig(authserv: []u8, headers: []u8, domain: []u8, methods: [][]const u8, ns: [][]const u8) ArcConfig {
    return .{
        .authserv_id = authserv,
        .listen_addresses = &.{},
        .worker_threads = 1,
        .max_connections = worker_mod.DEFAULT_MAX_CONNECTIONS,
        .max_key_records = chain.DEFAULT_MAX_KEY_RECORDS,
        .max_evaluation_ms = deadline_mod.DEFAULT_MS,
        .pid_file = "/nonexistent",
        .foreground = true,
        .user = null,
        .umask = null,
        .dns_nameservers = ns,
        .dns_timeout_ms = 1234,
        .dns_retries = 3,
        .dns_cache_size = 77,
        .dns_negative_ttl = 88,
        .modes = &.{},
        .seal_domain = domain,
        .seal_selector = "sel",
        .seal_key_file = null,
        .signed_headers = headers,
        .local_auth_methods = methods,
        .strip_auth_results = true,
        .zmq_endpoint = null,
        .zmq_topic = "arc",
        .limits = .{},
        .min_key_bits = .{ .bits = 2048, .raised = false },
        .on_dns_error = .skip_seal,
    };
}

test "a reloaded snapshot does not borrow from the config it came from" {
    // Overwrite the source buffers to verify that the snapshot owns every string.
    const a = std.testing.allocator;

    const authserv = try a.dupe(u8, "mail.first.test");
    defer a.free(authserv);
    const headers = try a.dupe(u8, "from:to:subject");
    defer a.free(headers);
    const domain = try a.dupe(u8, "first.example");
    defer a.free(domain);

    const method = try a.dupe(u8, "spf");
    defer a.free(method);
    const methods = try a.alloc([]const u8, 1);
    defer a.free(methods);
    methods[0] = method;

    const server = try a.dupe(u8, "10.0.0.1");
    defer a.free(server);
    const ns = try a.alloc([]const u8, 1);
    defer a.free(ns);
    ns[0] = server;

    var snap = try Reloadable.init(a, scratchConfig(authserv, headers, domain, methods, ns));
    defer snap.deinit(a);

    // Scribble over every source string, including the list contents.
    @memset(authserv, 'X');
    @memset(headers, 'X');
    @memset(domain, 'X');
    @memset(method, 'X');
    @memset(server, 'X');

    try std.testing.expectEqualStrings("mail.first.test", snap.authserv_id);
    try std.testing.expectEqualStrings("from:to:subject", snap.signed_headers);
    try std.testing.expectEqualStrings("first.example", snap.seal_domain.?);
    try std.testing.expectEqual(@as(usize, 1), snap.local_auth_methods.len);
    try std.testing.expectEqualStrings("spf", snap.local_auth_methods[0]);
    try std.testing.expectEqual(@as(usize, 1), snap.dns_config.nameservers.len);
    try std.testing.expectEqualStrings("10.0.0.1", snap.dns_config.nameservers[0]);

    // Reloadable scalar fields are copied too.
    try std.testing.expectEqual(@as(u32, 2048), snap.min_key_bits);
    try std.testing.expectEqual(OnDnsError.skip_seal, snap.on_dns_error);
    try std.testing.expect(snap.strip_all);
    try std.testing.expectEqual(@as(u32, 1234), snap.dns_config.timeout_ms);
    try std.testing.expectEqual(@as(u32, 88), snap.dns_config.negative_ttl);
}

test "a snapshot that fails partway through frees what it had already copied" {
    // Exercise each allocation failure; `FailingAllocator` detects leaked blocks.
    var saw_success = false;
    var saw_failure = false;

    var fail_index: usize = 0;
    while (fail_index < 12) : (fail_index += 1) {
        const a = std.testing.allocator;

        const authserv = try a.dupe(u8, "mail.first.test");
        defer a.free(authserv);
        const headers = try a.dupe(u8, "from:to");
        defer a.free(headers);
        const domain = try a.dupe(u8, "first.example");
        defer a.free(domain);
        const methods = try a.alloc([]const u8, 2);
        defer a.free(methods);
        methods[0] = "spf";
        methods[1] = "dkim";
        const ns = try a.alloc([]const u8, 2);
        defer a.free(ns);
        ns[0] = "10.0.0.1";
        ns[1] = "10.0.0.2";

        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = fail_index });
        const cfg = scratchConfig(authserv, headers, domain, methods, ns);

        if (Reloadable.init(failing.allocator(), cfg)) |made| {
            saw_success = true;
            var snap = made;
            snap.deinit(failing.allocator());
        } else |_| {
            saw_failure = true;
        }

        // Neither path may leave allocations outstanding.
        try std.testing.expectEqual(failing.allocations, failing.deallocations);
    }

    // Verify that the loop covered both outcomes.
    try std.testing.expect(saw_failure);
    try std.testing.expect(saw_success);
}

test "the strip policy always claims arc, and carries strip_all through" {
    // ARC is always this daemon's asserted method; `strip_all` is reloadable.
    const a = std.testing.allocator;
    const authserv = try a.dupe(u8, "mail.first.test");
    defer a.free(authserv);
    const headers = try a.dupe(u8, "from");
    defer a.free(headers);
    const domain = try a.dupe(u8, "first.example");
    defer a.free(domain);
    const methods = try a.alloc([]const u8, 0);
    defer a.free(methods);
    const ns = try a.alloc([]const u8, 0);
    defer a.free(ns);

    var cfg = scratchConfig(authserv, headers, domain, methods, ns);
    cfg.strip_auth_results = false;

    var snap = try Reloadable.init(a, cfg);
    defer snap.deinit(a);

    const policy = snap.stripPolicy();
    try std.testing.expectEqual(@as(usize, 1), policy.own_methods.len);
    try std.testing.expectEqualStrings("arc", policy.own_methods[0]);
    try std.testing.expect(!policy.strip_all);
}
