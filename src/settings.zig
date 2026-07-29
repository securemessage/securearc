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
const dns_mod = securemilter.dns;
const header_scrub = securemilter.header_scrub;

const securemilter_crypto = @import("securemilter_crypto");
const crypto = securemilter_crypto.crypto;

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
    pid_file: []const u8,
    foreground: bool,
    user: ?[]const u8,
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
    on_dns_error: OnDnsError,
};
pub fn parseArcConfig(allocator: Allocator, cfg: *const config_mod.Config) !ArcConfig {
    const global = cfg.getSection("global") orelse return error.MissingGlobalSection;

    const authserv_id = global.get("AuthservID") orelse "localhost";
    const workers = global.getInt("WorkerThreads", u32, 0);
    const pid_file = global.getOrDefault("PidFile", "/var/run/securearc/securearc.pid");
    const foreground_val = global.getBool("Foreground", false);
    const user = global.get("User");

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
            const socket_str = section.get("Socket") orelse continue;
            const addr = listener_mod.ListenAddress.parse(socket_str) catch continue;
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

    if (addrs.items.len == 0) {
        try addrs.append(allocator, .{ .tcp = .{ .host = "0.0.0.0", .port = 8895 } });
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

    const dns_ns_raw = global.getOrDefault("DnsNameserver", "127.0.0.1");
    var ns_list: std.ArrayListUnmanaged([]const u8) = .{};
    var ns_iter = mem.splitSequence(u8, dns_ns_raw, ",");
    while (ns_iter.next()) |part| {
        const trimmed = mem.trim(u8, part, " \t");
        if (trimmed.len > 0) try ns_list.append(allocator, trimmed);
    }
    const dns_nameservers = try ns_list.toOwnedSlice(allocator);
    // Owned from here on, so it needs unwinding of its own: everything above is
    // still an ArrayList with an errdefer, but this slice is not. Without this,
    // any `try` added below silently leaks it — which is exactly what the
    // On-DNSError validation did until it was moved to the top of the function.
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
    var methods: std.ArrayListUnmanaged([]const u8) = .{};
    errdefer methods.deinit(allocator);
    if (global.get("LocalAuthMethods")) |raw| {
        var it = mem.splitSequence(u8, raw, ",");
        while (it.next()) |part| {
            const trimmed = mem.trim(u8, part, " \t");
            if (trimmed.len > 0) try methods.append(allocator, trimmed);
        }
    }

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

    const zmq_endpoint = global.get("ZmqEndpoint");
    const zmq_topic = global.getOrDefault("ZmqTopic", "arc");

    return .{
        .authserv_id = authserv_id,
        .listen_addresses = try addrs.toOwnedSlice(allocator),
        .worker_threads = workers,
        .pid_file = pid_file,
        .foreground = foreground_val,
        .user = user,
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
        .local_auth_methods = try methods.toOwnedSlice(allocator),
        .strip_auth_results = strip_auth_results,
        .zmq_endpoint = zmq_endpoint,
        .zmq_topic = zmq_topic,
        .limits = limits,
        .min_key_bits = min_key_bits,
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
