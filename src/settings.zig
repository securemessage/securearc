//! SecureARC configuration: listener modes, the DNS-failure policy, and the
//! parser that turns an INI file into an `ArcConfig`.
//!
//! Split out of `main.zig` under megaplan Phase 10 R1, which capped that file at
//! 1698 lines against a 400-line standard. This was the cleanest seam available:
//! nothing in here touches the daemon's global state, so the entire layer is pure
//! parsing and is testable without starting a listener, a worker or a resolver.

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

/// Parse a `Mode` value from a config section.
///
/// An unrecognised value is an error rather than a silent fallback. The
/// previous parser tested three spellings and left the variable untouched on
/// anything else, so `Mode = sealing` ran a seal listener in verify mode and
/// said nothing — a typo that costs every message its ARC set.
pub fn parseMode(raw: []const u8) error{InvalidMode}!Mode {
    if (mem.eql(u8, raw, "verify")) return .verify_only;
    if (mem.eql(u8, raw, "seal")) return .seal_only;
    if (mem.eql(u8, raw, "both")) return .both;
    return error.InvalidMode;
}

/// Config-facing spelling of a mode, for logs.
///
/// The enum tags carry an `_only` suffix that appears neither in the config file
/// nor in the documented log format, and operators grep these lines. Kept
/// identical to the accepted `Mode =` values so a log line reads back as the
/// config that produced it.
pub fn modeLabel(m: Mode) []const u8 {
    return switch (m) {
        .verify_only => "verify",
        .seal_only => "seal",
        .both => "both",
    };
}

/// What a sealing listener does when a signer's key could not be fetched
/// because DNS failed transiently (audit A-12).
///
/// RFC 8617 §5.1.2 makes `cv=fail` permanent for the life of the message, so
/// the cheapest response locally — seal the failure and move on — is the one
/// that does irreversible harm to a third party's chain. The default is
/// therefore chosen by least *total* impact rather than least impact on this
/// host, which is also what OpenDKIM defaults `On-DNSError` to.
pub const OnDnsError = enum {
    /// Defer with a 4xx and let the sender retry. The only non-destructive
    /// answer for a hop that modifies the message, which is what sealing is
    /// for. Costs delay; risks burning the queue lifetime against a lame
    /// delegation that returns a transient-looking error indefinitely.
    tempfail,
    /// Add no ARC set and pass the message through untouched, reporting
    /// `arc=temperror`. Zero delay, and right for a relay that does not modify
    /// the message — but see the note in `doSeal`: if this hop *does* modify
    /// it, declining to seal only moves which hop breaks the chain.
    skip_seal,
    /// Seal `cv=fail`. The behaviour before A-12 was fixed, kept so an operator
    /// who depended on it can ask for it. Not recommended: it is the only
    /// option that inflicts permanent harm on a chain that may be perfectly
    /// good.
    seal_fail,
};

/// Parse an `On-DNSError` value, refusing anything unrecognised.
///
/// Silently defaulting here would pick a policy the operator did not ask for,
/// on the one code path whose whole purpose is to stop a transient fault from
/// becoming a permanent verdict.
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
    /// Per-worker cap on simultaneous connections, enforced in the accept path.
    ///
    /// No default on this field on purpose. It reached the worker as a hard-coded
    /// `DEFAULT_MAX_CONNECTIONS` while `MaxConnections` was already read by
    /// `securespf`, so the same key was honoured by one daemon and silently ignored
    /// by this one (audit L-2). A field that quietly supplies a constant when the
    /// caller forgets to set it is how that happens, so every construction site
    /// states it.
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
    ///
    /// One entry per socket rather than one value for the daemon: a host
    /// running `[listener:verify]` and `[listener:seal]` needs each socket to
    /// behave as configured, which is the whole point of having two.
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

/// The configuration a running daemon can adopt without a restart.
///
/// Published through an `Rcu` and read exactly once per message, which is what
/// makes reloading these values safe at all. A message is processed entirely under
/// one snapshot, so a SIGHUP arriving mid-message cannot leave the verify half
/// working from one configuration and the seal half from another, and cannot leave
/// the header-stripping pass using a different `authserv_id` from the stamp that
/// follows it. Workers announce quiescence only at the top of their event loop
/// (`reload.zig`), so the pointer stays valid for the message that took it.
///
/// Every string is owned. The values arrive pointing into a `Config` that
/// `reloadConfig` frees before it returns, so adopting them directly is what makes
/// the difference between a reload and a use-after-free.
///
/// What is deliberately *not* here is anything a running process cannot honestly
/// change: listen addresses and per-listener modes are bound to open sockets, and a
/// mode cannot change under an established connection; the `connection.Limits` caps
/// are fixed when a worker is spawned; `worker_threads`, `pid_file`, `user` and
/// `foreground` are startup decisions. Those stay restart-only and the man page says
/// so, per option, rather than leaving the operator to infer it.
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

    /// The forged-header strip rule for this snapshot.
    ///
    /// `own_methods` is `arc` and always will be: it names what *this* daemon
    /// asserts, which is a property of the program rather than of the deployment.
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

// L-2: `MaxConnections` was read by `securespf` and ignored here, so an operator
// who set it on this daemon got 256 and no diagnostic. The value has two
// consumers -- the accept-path cap in `worker.handleAccept` and the
// RLIMIT_NOFILE calculation in `daemon.calculateFdNeed` -- and wiring only one of
// them would raise the fd budget without raising the limit that budget was sized
// for, or the reverse.
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

// Same hazard as securedkim's, with sealing in place of signing: the loopback
// fallback took `default_mode` from `[global] Mode`, so a typo in the only
// listener's Socket could bring a listener written as `verify` up as a sealer --
// an unauthenticated sealing oracle for SealDomain, reachable locally.
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

// The implicit listener binds loopback, never 0.0.0.0.
//
// Until 2026-07-29 it bound 0.0.0.0 and nothing tested it. On a seal listener a
// reachable port is an unauthenticated signing oracle for the sealing domain; on a
// verify listener it dictates the Authentication-Results this host stamps, which is
// X-1/M-1 without needing to forge a header. The milter protocol authenticates
// nobody, so reachability IS authorization.
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

// A safe default, not a policy override: an operator whose Postfix lives in another
// jail must still be able to ask for a routable socket. `parse config minimal`
// above already uses 0.0.0.0 explicitly, so that path stays covered too.
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

    // A sealer that authenticates nothing locally must not vouch for anything.
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

// A-2 regression. Before the fix, `mode` was one variable written by every
// listener section in turn, so this config ran BOTH sockets in seal mode and
// the verify listener silently sealed.
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

// Declaration order in the file decides the index, because that is the order
// the worker binds them in and therefore the index it reports on a connection.
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

// The implicit default listener must still get a mode, or `modes` and
// `listen_addresses` fall out of step and every index lookup is wrong.
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

    // Underscores are the enum tag spelling, not the config spelling; accepting
    // them would give two ways to write one value.
    try std.testing.expectError(error.InvalidOnDnsError, parseOnDnsError("skip_seal"));
    try std.testing.expectError(error.InvalidOnDnsError, parseOnDnsError("Tempfail"));
    try std.testing.expectError(error.InvalidOnDnsError, parseOnDnsError("defer"));
    try std.testing.expectError(error.InvalidOnDnsError, parseOnDnsError(""));
}

// The default is the one that cannot permanently damage a third party's chain,
// even though it is not the cheapest for this host.
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

// Found by an end-to-end lab test whose own `printf >> config` appended the
// setting after the last section header, so it landed in [listener:seal] and was
// ignored — the daemon used the default and said nothing. Refusing is the same
// answer A-2 got.
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

// --- Reloadable: the snapshot SIGHUP publishes (audit A-14) -------------------
//
// This is fresh memory-management code on the reload path, and X-11 was a
// borrow-versus-own mistake that shipped because nothing tested the contract. The
// two properties worth pinning are that the snapshot is genuinely independent of the
// config it was built from, and that a failure partway through building one leaks
// nothing.

/// An `ArcConfig` whose strings live in `buf`, so a test can scribble over the
/// originals afterwards and see whether the snapshot noticed.
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
    // The property that makes reload safe rather than a use-after-free:
    // `reloadConfig` frees the parsed `Config` before it returns, so anything the
    // snapshot still points at is gone by the time the next message reads it. Tested
    // by overwriting the source buffers rather than by freeing them, so the result is
    // a deterministic comparison instead of a hope that the allocator notices.
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

    // Scalars come across too, including the two an operator would change during an
    // incident and that A-14 made silently ineffective.
    try std.testing.expectEqual(@as(u32, 2048), snap.min_key_bits);
    try std.testing.expectEqual(OnDnsError.skip_seal, snap.on_dns_error);
    try std.testing.expect(snap.strip_all);
    try std.testing.expectEqual(@as(u32, 1234), snap.dns_config.timeout_ms);
    try std.testing.expectEqual(@as(u32, 88), snap.dns_config.negative_ttl);
}

test "a snapshot that fails partway through frees what it had already copied" {
    // Six separate allocations plus the per-element dupes inside two lists, each
    // guarded by its own errdefer. Stated as a property over every allocation the
    // function performs rather than against a hand-picked index, so it cannot rot as
    // the field list changes -- the same shape as the X-8 test over `emitArcSet`.
    //
    // `FailingAllocator` reports any block still outstanding when the test ends, so a
    // missing errdefer fails here rather than becoming a leak on every SIGHUP that
    // happens to land under memory pressure.
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

        // Nothing outstanding on either path.
        try std.testing.expectEqual(failing.allocations, failing.deallocations);
    }

    // Guard against the loop passing because it exercised nothing.
    try std.testing.expect(saw_failure);
    try std.testing.expect(saw_success);
}

test "the strip policy always claims arc, and carries strip_all through" {
    // `own_methods` names what this daemon asserts, so it is a property of the
    // program. `strip_all` is the operator's, and it is reloadable.
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
