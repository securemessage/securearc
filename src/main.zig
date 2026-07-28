const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const config_mod = securemilter.config;
const listener_mod = securemilter.listener;
const connection_mod = securemilter.connection;
const worker_mod = securemilter.worker;
const daemon_mod = securemilter.daemon;
const auth_results = securemilter.auth_results;
const commands = securemilter.milter.commands;
const codec = securemilter.milter.codec;
const responses = securemilter.milter.responses;
const negotiate = securemilter.milter.negotiate;
const dns_mod = securemilter.dns;
const zmq = securemilter.zmq;
const log = securemilter.log;
const header_scrub = securemilter.header_scrub;

const securemilter_crypto = @import("securemilter_crypto");
const crypto = securemilter_crypto.crypto;

pub const arc = @import("arc.zig");
pub const chain = @import("chain.zig");
pub const seal = @import("seal.zig");

/// Listener mode for ARC processing.
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
fn modeLabel(m: Mode) []const u8 {
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

const reload_mod = securemilter.reload;
const rcu_mod = securemilter.rcu;

// Module-level config set before worker spawn, read-only during runtime.
var g_authserv_id: []const u8 = "localhost";
var g_dns_config: dns_mod.ResolverConfig = .{};
var g_modes: []const Mode = &.{};
var g_seal_domain: ?[]const u8 = null;
var g_seal_selector: ?[]const u8 = null;

/// Smallest RSA modulus accepted on an AMS or ARC-Seal signature.
///
/// Set once at startup and read by every worker thereafter. Kept out of
/// `connection.Limits` because that struct is shared by all four daemons and
/// only the two that verify signatures have any use for this.
var g_min_key_bits: u32 = crypto.RFC8301_MIN_RSA_BITS;
/// Policy for a transient DNS failure on a sealing listener (audit A-12).
///
/// Daemon-wide rather than per-listener, deliberately. Per-listener would mean
/// another array parallel to `g_modes`, and the value is meaningless on a verify
/// listener anyway: verifying is fixed at `arc=temperror` and deliver, because a
/// verifier writes no permanent verdict into the message and so has nothing to
/// decide. If a future deployment needs per-listener sealing policy that is an
/// additive change.
var g_on_dns_error: OnDnsError = .tempfail;
/// Seal key behind an RCU container.
///
/// A single ARC set is signed twice — once for the AMS, once for the AS — and
/// both signatures must come from the same key or the set is internally
/// inconsistent and unverifiable. The previous code held `&g_seal_key.?`
/// across both calls while SIGHUP overwrote the struct underneath, which
/// could straddle a reload and also leaked the old EVP_PKEY every time
/// (audit X-2).
const SealKeyRcu = rcu_mod.Rcu(crypto.SigningKey);
var g_seal_key: SealKeyRcu = undefined;

fn freeSealKey(allocator: Allocator, key: *crypto.SigningKey) void {
    key.deinit();
    allocator.destroy(key);
}

fn boxSealKey(allocator: Allocator, key: crypto.SigningKey) !*crypto.SigningKey {
    const boxed = try allocator.create(crypto.SigningKey);
    boxed.* = key;
    return boxed;
}
var g_signed_headers: []const u8 = "from:to:subject:date:message-id";
var g_local_auth_methods: []const []const u8 = &.{};
var g_strip_policy: header_scrub.StripPolicy = .{ .own_methods = &.{"arc"} };
var g_zmq_endpoint: ?[]const u8 = null;
var g_zmq_topic: []const u8 = "arc";
var g_allocator: Allocator = undefined;
var g_config_path: []const u8 = "/usr/local/etc/securearc/securearc.conf";
var g_health_monitor: ?*dns_mod.HealthMonitor = null;
var g_config_gen: reload_mod.ConfigGeneration = reload_mod.ConfigGeneration.init();

// Thread-local ZMQ publisher (one socket per worker thread — ZMQ thread-safety)
threadlocal var tl_publisher: ?zmq.Publisher = null;

fn getPublisher() *zmq.Publisher {
    if (tl_publisher == null) {
        tl_publisher = zmq.Publisher.init(g_zmq_endpoint, g_zmq_topic);
    }
    return &tl_publisher.?;
}

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

fn usageError() error{InvalidArgument} {
    log.err("usage: securearc -c <config-file>", .{});
    return error.InvalidArgument;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    g_allocator = allocator;

    // Parse command-line: securearc -c /path/to/config
    var args = std.process.args();
    _ = args.next();
    const flag = args.next() orelse return usageError();
    if (!std.mem.eql(u8, flag, "-c")) return usageError();
    const config_path = args.next() orelse return usageError();
    g_config_path = config_path;

    var cfg = config_mod.parseFile(allocator, config_path) catch |err| {
        log.err("failed to load config {s}: {}", .{ config_path, err });
        return err;
    };
    defer cfg.deinit();

    const arc_cfg = parseArcConfig(allocator, &cfg) catch |err| {
        log.err("config parse error: {}", .{err});
        return err;
    };

    // Initialize logging from config
    const log_cfg = if (cfg.global()) |g| log.LogConfig.fromSection(g, "securearc") else log.LogConfig.init(true, .mail, .info, "securearc");
    log.initGlobal(&log_cfg);
    log.initThread();

    // Set module-level globals
    g_authserv_id = arc_cfg.authserv_id;
    g_dns_config = .{
        .nameservers = arc_cfg.dns_nameservers,
        .timeout_ms = arc_cfg.dns_timeout_ms,
        .retries = arc_cfg.dns_retries,
        .cache_size = arc_cfg.dns_cache_size,
        .negative_ttl = arc_cfg.dns_negative_ttl,
    };

    g_modes = arc_cfg.modes;
    g_seal_domain = arc_cfg.seal_domain;
    g_seal_selector = arc_cfg.seal_selector;
    g_signed_headers = arc_cfg.signed_headers;
    g_local_auth_methods = arc_cfg.local_auth_methods;
    g_strip_policy = .{ .own_methods = &.{"arc"}, .strip_all = arc_cfg.strip_auth_results };
    g_zmq_endpoint = arc_cfg.zmq_endpoint;
    g_zmq_topic = arc_cfg.zmq_topic;
    g_min_key_bits = arc_cfg.min_key_bits.bits;
    g_on_dns_error = arc_cfg.on_dns_error;

    if (arc_cfg.min_key_bits.raised) {
        log.warn(
            "{s} below the RFC 8301 minimum: using {d} bits",
            .{ crypto.MIN_KEY_BITS_OPTION, arc_cfg.min_key_bits.bits },
        );
    }

    // Load seal key if configured
    g_seal_key = SealKeyRcu.init(allocator, freeSealKey);
    if (arc_cfg.seal_key_file) |key_path| {
        // The RFC floor, not the operator's MinimumKeyBits: that option is a
        // policy about keys other ADMDs publish. Sealing with an undersized key
        // is its own fault though — RFC 8301 §3.2 binds signers to 1024 bits
        // too, and a seal no downstream verifier will accept is worse than no
        // seal at all, because it claims a chain of custody that cannot be
        // checked.
        const min_bits = crypto.RFC8301_MIN_RSA_BITS;
        var key = crypto.loadRsaKeyFile(key_path, min_bits) catch |err| {
            if (err == error.RsaKeyTooSmall) {
                log.err(
                    "seal key {s} is below the RFC 8301 minimum of {d} bits: refusing to seal with it",
                    .{ key_path, min_bits },
                );
            } else {
                log.err("failed to load seal key {s}: {}", .{ key_path, err });
            }
            return err;
        };
        log.info("loaded {d}-bit seal key from {s}", .{ crypto.signingKeyBits(&key), key_path });
        const boxed = boxSealKey(allocator, key) catch |err| {
            key.deinit();
            log.err("failed to store seal key: {}", .{err});
            return err;
        };
        g_seal_key.publish(&g_config_gen, boxed) catch |err| {
            freeSealKey(allocator, boxed);
            log.err("failed to publish seal key: {}", .{err});
            return err;
        };
    }

    // Daemonize — MUST happen before spawning any threads (fork only preserves calling thread)
    if (!arc_cfg.foreground) {
        daemon_mod.daemonize() catch |err| {
            log.err("daemonize failed: {}", .{err});
            return err;
        };
        log.initThread(); // re-init after fork (PID changed)
    }

    // Block the managed signals BEFORE spawning any thread, so every thread
    // inherits the mask and SIGHUP/SIGTERM can only be taken by sigwait in the
    // main thread. Ordering matters: this used to sit just above the worker
    // pool, leaving the health monitor thread below with SIGHUP unblocked and
    // able to take a reload signal and terminate the daemon (audit X-7).
    daemon_mod.ManagedSignals.blockForKqueue();

    // Start proactive DNS health monitor AFTER daemonize
    if (dns_mod.HealthMonitor.init(allocator, arc_cfg.dns_nameservers, 53, 5, 2000)) |monitor| {
        monitor.start() catch |err| {
            log.warn("DNS health monitor thread failed: {}", .{err});
        };
        g_health_monitor = monitor;
    } else |err| {
        log.warn("DNS health monitor init failed: {}, falling back to reactive", .{err});
    }

    daemon_mod.writePidFile(arc_cfg.pid_file) catch |err| {
        log.err("pid file write failed: {}", .{err});
    };
    defer daemon_mod.removePidFile(arc_cfg.pid_file);

    // Raise fd limit to calculated budget before dropping privileges
    const num_workers = if (arc_cfg.worker_threads == 0) @as(u32, @intCast(std.Thread.getCpuCount() catch 4)) else arc_cfg.worker_threads;
    const fd_need = daemon_mod.calculateFdNeed(num_workers, worker_mod.DEFAULT_MAX_CONNECTIONS, @intCast(arc_cfg.listen_addresses.len));
    daemon_mod.raiseFileLimit(fd_need);

    // Drop privileges after PID file is written, before workers spawn
    if (arc_cfg.user) |user| {
        daemon_mod.dropPrivileges(user) catch |err| {
            log.err("privilege drop to '{s}' failed: {}", .{ user, err });
            return err;
        };
    }

    log.info("SecureARC starting, AuthservID={s}, MinimumKeyBits={d}, listeners={d}", .{
        arc_cfg.authserv_id,
        arc_cfg.min_key_bits.bits,
        arc_cfg.listen_addresses.len,
    });

    // One line per socket. A single daemon-wide mode used to be logged even
    // when the config named two different ones, so the log agreed with the
    // config while the daemon did not (audit A-2).
    for (arc_cfg.modes, 0..) |m, i| {
        log.info("listener[{d}] mode={s}", .{ i, modeLabel(m) });
    }

    const required_actions = negotiate.ActionFlags{ .add_headers = true, .change_headers = true };

    const callbacks = worker_mod.Callbacks{
        .on_connect = onConnect,
        .on_helo = onHelo,
        .on_mail_from = onMailFrom,
        .on_header = onHeader,
        .on_eoh = onEoh,
        .on_body = onBody,
        .on_eom = onEom,
        .on_reload = onWorkerReload,
        .required_actions = required_actions,
        .limits = arc_cfg.limits,
    };

    const shutdown_pipe = try posix.pipe();
    defer posix.close(shutdown_pipe[0]);

    var threads = try worker_mod.spawnPoolWithReload(
        allocator,
        arc_cfg.worker_threads,
        arc_cfg.listen_addresses,
        callbacks,
        shutdown_pipe[0],
        &g_config_gen,
        worker_mod.DEFAULT_MAX_CONNECTIONS,
    );
    defer threads.deinit(allocator);

    daemon_mod.ManagedSignals.signalLoop(shutdown_pipe[1], reloadConfig);
    for (threads.items) |t| t.join();

    // Workers are joined: no seal is in progress, so the live key and any
    // retired ones can all be freed.
    g_seal_key.deinit();
    g_config_gen.deinit(allocator);

    if (g_health_monitor) |monitor| monitor.deinit();
}

// =============================================================================
// Milter Callbacks
// =============================================================================

fn onConnect(conn: *connection_mod.Connection, _: commands.ConnectInfo) u8 {
    _ = conn;
    return @intFromEnum(responses.Code.@"continue");
}

fn onHelo(conn: *connection_mod.Connection, _: []const u8) u8 {
    _ = conn;
    return @intFromEnum(responses.Code.@"continue");
}

fn onMailFrom(conn: *connection_mod.Connection, _: []const u8) u8 {
    _ = conn;
    return @intFromEnum(responses.Code.@"continue");
}

fn onHeader(conn: *connection_mod.Connection, _: []const u8, _: []const u8) u8 {
    _ = conn;
    return @intFromEnum(responses.Code.@"continue");
}

fn onEoh(conn: *connection_mod.Connection) u8 {
    _ = conn;
    return @intFromEnum(responses.Code.@"continue");
}

fn onBody(conn: *connection_mod.Connection, data: []const u8) u8 {
    // See securedkim's onBody: the connection latches the overflow and
    // end-of-message declines to validate or seal, rather than hashing a body
    // the MTA is not delivering (audit X-4). Log only the chunk that trips it.
    const already_tripped = conn.body_overflow;
    conn.appendBody(data) catch |e| {
        if (!already_tripped) {
            const peer = conn.getPeerDisplay();
            if (e == error.BodyTooLarge) {
                log.warn(
                    "body exceeds MaxBodyBytes={d} from {s}[{s}]: message will not be validated or sealed",
                    .{ conn.limits.max_body_bytes, peer.name, peer.ip },
                );
            } else {
                log.err("body accumulation failed for {s}[{s}]: {}", .{ peer.name, peer.ip, e });
            }
        }
    };
    return @intFromEnum(responses.Code.@"continue");
}

fn onEom(conn: *connection_mod.Connection) u8 {
    const start_ns = std.time.nanoTimestamp();

    // Drop forged arc= claims before validating or sealing.
    _ = header_scrub.stripAuthResults(conn, g_authserv_id, g_strip_policy);

    const mode = modeFor(conn.listener_index);

    const result = switch (mode) {
        .verify_only => doVerify(conn),
        .seal_only => doSeal(conn),
        .both => blk: {
            _ = doVerify(conn);
            break :blk doSeal(conn);
        },
    };
    const elapsed_ms = @divFloor(std.time.nanoTimestamp() - start_ns, 1_000_000);
    const queue_id = conn.macros.queue_id orelse "-";
    const client_addr = conn.macros.client_addr orelse "unknown";
    const peer = conn.getPeerDisplay();
    log.info("id={s} peer={s}[{s}] client={s} listener={d} mode={s} elapsed={d}ms", .{
        queue_id,
        peer.name,
        peer.ip,
        client_addr,
        conn.listener_index,
        modeLabel(mode),
        elapsed_ms,
    });
    return result;
}

/// Mode for the socket a connection arrived on (audit A-2).
///
/// Every worker binds every configured address, so the index the worker
/// records on a connection indexes the same list `parseArcConfig` built and
/// the lookup is always in range. It is still bounds-checked rather than
/// asserted: an out-of-range index is a wiring bug, and aborting a running
/// mail server is a worse response to one than falling back to the mode that
/// neither seals nor rewrites and saying so loudly.
fn modeFor(listener_index: usize) Mode {
    if (listener_index < g_modes.len) return g_modes[listener_index];
    log.err(
        "listener index {d} has no configured mode ({d} known): falling back to verify",
        .{ listener_index, g_modes.len },
    );
    return .verify_only;
}

fn doVerify(conn: *connection_mod.Connection) u8 {
    // An incomplete copy cannot validate a chain: every AMS in it covers the
    // body, so a truncated body makes each one fail on content grounds rather
    // than on the chain's own merits. arc=fail would blame the sender for our
    // resource limit, so this is temperror (RFC 8617 5.2 treats it as a
    // transient verification failure).
    if (conn.contentTruncated()) {
        addArHeaderSimple(conn, "arc", "temperror", "message too large to validate");
        publishEvent(conn.allocator, "verify", "temperror", 0);
        return @intFromEnum(responses.Code.@"continue");
    }

    // Build header list in arc.Header format
    var arc_headers: std.ArrayListUnmanaged(arc.Header) = .{};
    defer arc_headers.deinit(conn.allocator);

    for (conn.headers.items) |hdr| {
        arc_headers.append(conn.allocator, .{ .name = hdr.name, .value = hdr.value }) catch continue;
    }

    // Parse ARC sets from headers.
    //
    // A chain that does not parse is a broken chain, not an absent one
    // (RFC 8617 §5.1.2). Answering arc=none here would let a sender downgrade
    // a failed chain to "unsealed" simply by malforming it — and, before the
    // parser rejected gaps, by appending a garbage set above a genuine one.
    const sets = arc.parseArcSets(conn.allocator, arc_headers.items) catch |err| {
        if (err == error.OutOfMemory) return @intFromEnum(responses.Code.tempfail);
        const reason = arc.describeChainError(err);
        addArHeaderSimple(conn, "arc", "fail", reason);
        publishEvent(conn.allocator, "verify", "fail", 0);
        return @intFromEnum(responses.Code.@"continue");
    };
    defer conn.allocator.free(sets);

    if (sets.len == 0) {
        addArHeaderSimple(conn, "arc", "none", null);
        publishEvent(conn.allocator, "verify", "none", 0);
        return @intFromEnum(responses.Code.@"continue");
    }

    // Validate chain. The truncation check at the top of doVerify established
    // the body is whole.
    const body_data = conn.getBody() orelse return @intFromEnum(responses.Code.@"continue");
    var resolver = dns_mod.Resolver.initWithMonitor(conn.allocator, g_dns_config, g_health_monitor);
    defer resolver.deinit();

    const result = chain.validateChain(
        conn.allocator,
        &resolver,
        sets,
        arc_headers.items,
        body_data,
        g_min_key_bits,
    );

    // A verifier reports what it found and never writes a permanent verdict
    // into the message, so an unevaluable chain is `arc=temperror`: honest,
    // revisable by the next hop, and not configurable (audit A-12). Only a
    // sealer has a policy decision to make, because only a sealer records
    // something RFC 8617 §5.1.2 forbids anyone downstream from revising.
    switch (result.evaluation) {
        .complete => {},
        .dns_temp_error => {
            addArHeaderSimple(conn, "arc", "temperror", result.failure_reason);
            publishEvent(conn.allocator, "verify", "temperror", result.highest_instance);
            return @intFromEnum(responses.Code.@"continue");
        },
        // Our fault, so the sender should retry rather than have our failure
        // recorded against their chain (audit A-12a). Unconditional: a local
        // fault is not a policy question.
        .internal_error => {
            log.err("internal error validating ARC chain: {s}", .{result.failure_reason orelse "unknown"});
            return @intFromEnum(responses.Code.tempfail);
        },
    }

    addArHeaderSimple(conn, "arc", result.status.toString(), result.failure_reason);
    publishEvent(conn.allocator, "verify", result.status.toString(), result.highest_instance);
    return @intFromEnum(responses.Code.@"continue");
}

fn doSeal(conn: *connection_mod.Connection) u8 {
    // A seal is an attestation over content. Sealing a copy we know to be
    // incomplete would hand the next hop a chain that cannot validate and name
    // this ADMD as the one that broke it (audit X-4). Pass through unsealed.
    if (conn.contentTruncated()) {
        const peer = conn.getPeerDisplay();
        log.warn(
            "not sealing message from {s}[{s}]: accumulated copy is incomplete",
            .{ peer.name, peer.ip },
        );
        return @intFromEnum(responses.Code.@"continue");
    }

    const domain = g_seal_domain orelse return @intFromEnum(responses.Code.@"continue");
    const selector = g_seal_selector orelse return @intFromEnum(responses.Code.@"continue");

    // One key for the whole set. Acquired once here and used for both the AMS
    // and the AS below: a reload landing between the two signatures must not
    // be able to sign the halves of one ARC set with different keys.
    const sign_key = g_seal_key.get() orelse return @intFromEnum(responses.Code.@"continue");

    // Determine instance number: count existing ARC sets + 1
    var arc_headers: std.ArrayListUnmanaged(arc.Header) = .{};
    defer arc_headers.deinit(conn.allocator);

    for (conn.headers.items) |hdr| {
        arc_headers.append(conn.allocator, .{ .name = hdr.name, .value = hdr.value }) catch continue;
    }

    // A chain we cannot parse cannot be extended: sealing it would attest to a
    // sequence we were unable to read. Pass the message through unsealed.
    const sets = arc.parseArcSets(conn.allocator, arc_headers.items) catch |err| {
        if (err != error.OutOfMemory) {
            log.warn("not sealing: {s}", .{arc.describeChainError(err)});
        }
        return @intFromEnum(responses.Code.@"continue");
    };
    defer conn.allocator.free(sets);

    const new_instance: u8 = if (sets.len > 0) sets[sets.len - 1].instance + 1 else 1;
    if (new_instance > arc.MAX_INSTANCES) return @intFromEnum(responses.Code.@"continue");

    // Determine chain status for our seal.
    //
    // This is where A-12 lived: `vr.status` was taken as the cv= value whatever
    // produced it, so a nameserver blip while fetching a previous hop's key
    // sealed cv=fail — permanent for the life of the message under RFC 8617
    // §5.1.2, and indistinguishable to every later hop from a forged signature.
    const cv: arc.ChainValidation = if (sets.len == 0) .none else blk: {
        const body_data = conn.getBody() orelse break :blk arc.ChainValidation.fail;
        var resolver = dns_mod.Resolver.initWithMonitor(conn.allocator, g_dns_config, g_health_monitor);
        defer resolver.deinit();
        const vr = chain.validateChain(conn.allocator, &resolver, sets, arc_headers.items, body_data, g_min_key_bits);
        switch (vr.evaluation) {
            .complete => break :blk vr.status,
            .internal_error => {
                // Ours, not theirs. Defer unconditionally rather than record it
                // against the chain (audit A-12a).
                log.err("not sealing: internal error validating the chain: {s}", .{vr.failure_reason orelse "unknown"});
                return @intFromEnum(responses.Code.tempfail);
            },
            .dns_temp_error => switch (g_on_dns_error) {
                .tempfail => {
                    // ASCII only: syslog rendered an em dash here as escaped
                    // bytes, which is noise in the one log line an operator
                    // reads when mail starts deferring.
                    log.warn(
                        "deferring: {s}; sealing cv=fail would be permanent (On-DNSError=tempfail)",
                        .{vr.failure_reason orelse "transient DNS failure"},
                    );
                    return @intFromEnum(responses.Code.tempfail);
                },
                // Pass through with no ARC set of ours. Safe for a hop that does
                // not modify the message; if this hop does modify it, the
                // previous hop's AMS now covers content we changed and the next
                // hop computes cv=fail — so this moves who breaks the chain
                // rather than saving it. That is the operator's call to make,
                // because only they know whether this path rewrites mail.
                .skip_seal => {
                    log.warn(
                        "not sealing: {s} (On-DNSError=skip-seal)",
                        .{vr.failure_reason orelse "transient DNS failure"},
                    );
                    addArHeaderSimple(conn, "arc", "temperror", vr.failure_reason);
                    publishEvent(conn.allocator, "seal", "temperror", vr.highest_instance);
                    return @intFromEnum(responses.Code.@"continue");
                },
                .seal_fail => {
                    log.warn(
                        "sealing cv=fail after a transient DNS failure ({s}) because On-DNSError=seal-fail",
                        .{vr.failure_reason orelse "transient DNS failure"},
                    );
                    break :blk arc.ChainValidation.fail;
                },
            },
        }
    };

    // Build AAR content from the results this ADMD produced
    const ar_content = buildAarContent(conn) orelse
        return @intFromEnum(responses.Code.@"continue");
    defer conn.allocator.free(ar_content);

    // Build ARC-Authentication-Results header and prepend
    const aar = std.fmt.allocPrint(conn.allocator, "i={d}; {s}", .{ new_instance, ar_content }) catch
        return @intFromEnum(responses.Code.@"continue");
    defer conn.allocator.free(aar);

    prependHeader(conn, "ARC-Authentication-Results", aar);

    // Build AMS: sign the message (same as DKIM signing). Guarded at the top of
    // doSeal, so the body here is the whole body.
    const body_data = conn.getBody() orelse return @intFromEnum(responses.Code.@"continue");
    const canon_mod = securemilter_crypto.canon;

    // Canonicalize body and compute body hash
    var body_canon = canon_mod.BodyCanonicalizer.init(conn.allocator, .relaxed);
    defer body_canon.deinit();
    body_canon.update(body_data) catch return @intFromEnum(responses.Code.@"continue");
    const canon_body = body_canon.finish() catch return @intFromEnum(responses.Code.@"continue");
    defer conn.allocator.free(canon_body);
    const body_hash_raw = crypto.sha256(canon_body);
    const body_hash_b64 = crypto.base64Encode(conn.allocator, &body_hash_raw) catch
        return @intFromEnum(responses.Code.@"continue");
    defer conn.allocator.free(body_hash_b64);

    // Build AMS template (pre-folded — SAME format used for both signing input AND
    // the header prepended to the message, ensuring byte-identical canonicalization)
    const ams_template = std.fmt.allocPrint(
        conn.allocator,
        "i={d}; a=rsa-sha256;\r\n\tc=relaxed/relaxed; d={s}; s={s};\r\n\th={s};\r\n\tbh={s};\r\n\tb=",
        .{ new_instance, domain, selector, g_signed_headers, body_hash_b64 },
    ) catch return @intFromEnum(responses.Code.@"continue");
    defer conn.allocator.free(ams_template);

    // Canonicalize selected headers for AMS signing input
    var ams_input: std.ArrayListUnmanaged(u8) = .{};
    defer ams_input.deinit(conn.allocator);
    buildSigningHeaders(conn, &ams_input) catch return @intFromEnum(responses.Code.@"continue");

    // Append AMS header template (with empty b=) as final line (no trailing CRLF)
    const ams_full_template = std.fmt.allocPrint(conn.allocator, "ARC-Message-Signature: {s}", .{ams_template}) catch
        return @intFromEnum(responses.Code.@"continue");
    defer conn.allocator.free(ams_full_template);
    const canon_ams_tmpl = canon_mod.canonicalizeHeader(conn.allocator, .relaxed, ams_full_template) catch
        return @intFromEnum(responses.Code.@"continue");
    defer conn.allocator.free(canon_ams_tmpl);
    ams_input.appendSlice(conn.allocator, canon_ams_tmpl) catch
        return @intFromEnum(responses.Code.@"continue");

    // Sign AMS
    const ams_sig_raw = crypto.rsaSign(conn.allocator, sign_key.rsa_pkey.?, ams_input.items) catch
        return @intFromEnum(responses.Code.@"continue");
    defer conn.allocator.free(ams_sig_raw);
    const ams_sig_b64 = crypto.base64Encode(conn.allocator, ams_sig_raw) catch
        return @intFromEnum(responses.Code.@"continue");
    defer conn.allocator.free(ams_sig_b64);

    // Final AMS header value: same pre-folded template + signature (folded base64)
    const folded_ams_sig = foldBase64(conn.allocator, ams_sig_b64) catch ams_sig_b64;
    const ams_value = std.fmt.allocPrint(
        conn.allocator,
        "i={d}; a=rsa-sha256;\r\n\tc=relaxed/relaxed; d={s}; s={s};\r\n\th={s};\r\n\tbh={s};\r\n\tb={s}",
        .{ new_instance, domain, selector, g_signed_headers, body_hash_b64, folded_ams_sig },
    ) catch return @intFromEnum(responses.Code.@"continue");
    defer conn.allocator.free(ams_value);
    prependHeader(conn, "ARC-Message-Signature", ams_value);

    // Build ARC-Seal: signs over all prior ARC headers + current AAR + AMS + AS(empty b=)
    const as_template = std.fmt.allocPrint(
        conn.allocator,
        "i={d}; cv={s}; a=rsa-sha256; d={s}; s={s};\r\n\tb=",
        .{ new_instance, cv.toString(), domain, selector },
    ) catch return @intFromEnum(responses.Code.@"continue");
    defer conn.allocator.free(as_template);

    // Build seal signing input
    var seal_input: std.ArrayListUnmanaged(u8) = .{};
    defer seal_input.deinit(conn.allocator);
    buildSealInput(conn, &seal_input, sets, aar, ams_value, as_template) catch
        return @intFromEnum(responses.Code.@"continue");

    // Sign seal
    const seal_sig_raw = crypto.rsaSign(conn.allocator, sign_key.rsa_pkey.?, seal_input.items) catch
        return @intFromEnum(responses.Code.@"continue");
    defer conn.allocator.free(seal_sig_raw);
    const seal_sig_b64 = crypto.base64Encode(conn.allocator, seal_sig_raw) catch
        return @intFromEnum(responses.Code.@"continue");
    defer conn.allocator.free(seal_sig_b64);

    // Final AS header value (pre-folded)
    const as_value = std.fmt.allocPrint(
        conn.allocator,
        "i={d}; cv={s}; a=rsa-sha256; d={s}; s={s};\r\n\tb={s}",
        .{ new_instance, cv.toString(), domain, selector, foldBase64(conn.allocator, seal_sig_b64) catch seal_sig_b64 },
    ) catch return @intFromEnum(responses.Code.@"continue");
    defer conn.allocator.free(as_value);
    prependHeader(conn, "ARC-Seal", as_value);

    publishEvent(conn.allocator, "seal", cv.toString(), new_instance);
    return @intFromEnum(responses.Code.accept);
}

/// Canonicalize headers listed in g_signed_headers and append to buf.
fn buildSigningHeaders(conn: *connection_mod.Connection, buf: *std.ArrayListUnmanaged(u8)) !void {
    const canon_mod = securemilter_crypto.canon;
    var h_rest: []const u8 = g_signed_headers;
    while (h_rest.len > 0) {
        const colon_pos = mem.indexOfScalar(u8, h_rest, ':');
        const hdr_name = if (colon_pos) |cp| h_rest[0..cp] else h_rest;
        h_rest = if (colon_pos) |cp| h_rest[cp + 1 ..] else "";

        const trimmed = mem.trim(u8, hdr_name, &std.ascii.whitespace);
        if (trimmed.len == 0) continue;

        // Find last occurrence of this header
        var found: ?[]const u8 = null;
        for (conn.headers.items) |hdr| {
            if (eqlIgnoreCase(hdr.name, trimmed)) {
                found = hdr.value;
            }
        }
        if (found) |value| {
            const full = try std.fmt.allocPrint(conn.allocator, "{s}: {s}", .{ trimmed, value });
            defer conn.allocator.free(full);
            const canonicalized = try canon_mod.canonicalizeHeader(conn.allocator, .relaxed, full);
            defer conn.allocator.free(canonicalized);
            try buf.appendSlice(conn.allocator, canonicalized);
            try buf.appendSlice(conn.allocator, "\r\n");
        }
    }
}

/// Build the seal signing input: prior ARC headers + current AAR + AMS + AS template.
fn buildSealInput(
    conn: *connection_mod.Connection,
    buf: *std.ArrayListUnmanaged(u8),
    prior_sets: []const arc.ArcSet,
    current_aar: []const u8,
    current_ams_value: []const u8,
    as_template: []const u8,
) !void {
    const canon_mod = securemilter_crypto.canon;

    // Prior sets: canonicalize all 3 headers for each
    for (prior_sets) |prior| {
        try appendCanonHdr(conn.allocator, buf, "ARC-Authentication-Results", prior.aar_value);
        try appendCanonHdr(conn.allocator, buf, "ARC-Message-Signature", prior.ams_value);
        try appendCanonHdr(conn.allocator, buf, "ARC-Seal", prior.as_value);
    }

    // Current instance: AAR + AMS
    try appendCanonHdr(conn.allocator, buf, "ARC-Authentication-Results", current_aar);
    try appendCanonHdr(conn.allocator, buf, "ARC-Message-Signature", current_ams_value);

    // AS header with empty b= (no trailing CRLF — last header in signing input)
    const as_full = try std.fmt.allocPrint(conn.allocator, "ARC-Seal: {s}", .{as_template});
    defer conn.allocator.free(as_full);
    const canon_as = try canon_mod.canonicalizeHeader(conn.allocator, .relaxed, as_full);
    defer conn.allocator.free(canon_as);
    try buf.appendSlice(conn.allocator, canon_as);
}

fn appendCanonHdr(allocator: Allocator, buf: *std.ArrayListUnmanaged(u8), name: []const u8, value: []const u8) !void {
    const canon_mod = securemilter_crypto.canon;
    const full = try std.fmt.allocPrint(allocator, "{s}: {s}", .{ name, value });
    defer allocator.free(full);
    const canonicalized = try canon_mod.canonicalizeHeader(allocator, .relaxed, full);
    defer allocator.free(canonicalized);
    try buf.appendSlice(allocator, canonicalized);
    try buf.appendSlice(allocator, "\r\n");
}

/// Assemble the ARC-Authentication-Results content from results this ADMD
/// actually produced (RFC 8617 §5.1.1).
///
/// An A-R header qualifies only if it claims our authserv-id *and* every
/// method it asserts is listed in `LocalAuthMethods`. Anything else is a
/// sender-supplied claim: copying it here would have this host cryptographically
/// vouch for authentication it never performed. A host that lists no local
/// methods therefore seals an honest `none`.
///
/// Caller owns the returned slice. Returns null only on allocation failure.
fn buildAarContent(conn: *connection_mod.Connection) ?[]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .{};
    errdefer buf.deinit(conn.allocator);

    var found = false;
    for (conn.headers.items) |hdr| {
        if (!eqlIgnoreCase(hdr.name, "Authentication-Results")) continue;
        if (!auth_results.matchesAuthservId(hdr.value, g_authserv_id)) continue;
        if (!auth_results.assertsAnyMethod(hdr.value, g_local_auth_methods)) continue;
        if (auth_results.assertsMethodOutside(hdr.value, g_local_auth_methods)) {
            log.warn("ignoring Authentication-Results claiming our authserv-id with non-local methods", .{});
            continue;
        }

        // Keep the raw result text (properties included); drop the repeated
        // authserv-id, which the AAR states once up front.
        const results = resultsPart(hdr.value) orelse continue;
        if (!found) {
            buf.appendSlice(conn.allocator, g_authserv_id) catch return null;
            found = true;
        }
        buf.appendSlice(conn.allocator, "; ") catch return null;
        buf.appendSlice(conn.allocator, results) catch return null;
    }

    if (!found) {
        buf.deinit(conn.allocator);
        return std.fmt.allocPrint(conn.allocator, "{s}; none", .{g_authserv_id}) catch null;
    }
    return buf.toOwnedSlice(conn.allocator) catch null;
}

/// The portion of an A-R value after the authserv-id, trimmed of surrounding
/// whitespace and trailing separators.
fn resultsPart(header_value: []const u8) ?[]const u8 {
    const trimmed = mem.trimLeft(u8, header_value, &std.ascii.whitespace);
    const semi = mem.indexOfScalar(u8, trimmed, ';') orelse return null;
    const rest = mem.trim(u8, trimmed[semi + 1 ..], &std.ascii.whitespace);
    const cleaned = mem.trim(u8, rest, ";");
    const result = mem.trim(u8, cleaned, &std.ascii.whitespace);
    return if (result.len == 0) null else result;
}

/// Fold a base64 string by inserting CRLF+TAB every 76 characters.
/// Prevents Postfix from introducing mid-token folds at arbitrary positions.
fn foldBase64(allocator: Allocator, b64: []const u8) ![]const u8 {
    const chunk_size = 76;
    if (b64.len <= chunk_size) return b64;

    var result: std.ArrayListUnmanaged(u8) = .{};
    errdefer result.deinit(allocator);

    var offset: usize = 0;
    while (offset < b64.len) {
        const end = @min(offset + chunk_size, b64.len);
        try result.appendSlice(allocator, b64[offset..end]);
        if (end < b64.len) {
            try result.appendSlice(allocator, "\r\n\t");
        }
        offset = end;
    }
    return result.toOwnedSlice(allocator);
}

fn prependHeader(conn: *connection_mod.Connection, name: []const u8, value: []const u8) void {
    const hdr_payload = responses.addHeader(conn.allocator, name, value) catch return;
    defer conn.allocator.free(hdr_payload);
    codec.writePacket(conn.fd, hdr_payload) catch {};
}

fn addArHeaderSimple(
    conn: *connection_mod.Connection,
    method: []const u8,
    result_str: []const u8,
    reason: ?[]const u8,
) void {
    const ar_value = auth_results.build(conn.allocator, g_authserv_id, &.{
        .{
            .method = method,
            .result = result_str,
            .reason = reason,
            .properties = &.{},
        },
    }) catch return;
    defer conn.allocator.free(ar_value);

    const hdr_payload = responses.addHeader(conn.allocator, "Authentication-Results", ar_value) catch return;
    defer conn.allocator.free(hdr_payload);
    codec.writePacket(conn.fd, hdr_payload) catch {};
}

fn publishEvent(allocator: Allocator, action: []const u8, result_str: []const u8, instance: u8) void {
    const json = std.fmt.allocPrint(allocator,
        \\{{"action":"{s}","result":"{s}","instance":{d}}}
    , .{ action, result_str, instance }) catch return;
    defer allocator.free(json);
    getPublisher().publish(json);
}

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (toLower(ca) != toLower(cb)) return false;
    }
    return true;
}

fn toLower(c: u8) u8 {
    if (c >= 'A' and c <= 'Z') return c + 32;
    return c;
}

// =============================================================================
// Reload
// =============================================================================

/// Main-thread reload callback: re-reads seal key on SIGHUP.
fn reloadConfig() void {
    // Re-read seal key file
    var cfg = config_mod.parseFile(g_allocator, g_config_path) catch {
        log.warn("reload: failed to re-read config file, keeping previous", .{});
        _ = g_config_gen.increment();
        return;
    };
    defer cfg.deinit();

    const arc_cfg = parseArcConfig(g_allocator, &cfg) catch {
        log.warn("reload: failed to parse config, keeping previous", .{});
        _ = g_config_gen.increment();
        return;
    };
    // parseArcConfig hands back four slices it allocated. Only the seal key
    // is adopted below; the rest were dropped on the floor here, leaking a
    // little more on every SIGHUP.
    defer {
        g_allocator.free(arc_cfg.listen_addresses);
        g_allocator.free(arc_cfg.modes);
        g_allocator.free(arc_cfg.dns_nameservers);
        g_allocator.free(arc_cfg.local_auth_methods);
    }

    if (arc_cfg.seal_key_file) |key_path| {
        const min_bits = crypto.RFC8301_MIN_RSA_BITS;
        if (crypto.loadRsaKeyFile(key_path, min_bits)) |new_key| {
            var key = new_key;
            if (boxSealKey(g_allocator, new_key)) |boxed| {
                if (g_seal_key.publish(&g_config_gen, boxed)) {
                    log.info("seal key reloaded from {s} ({d} awaiting reclamation)", .{
                        key_path,
                        g_seal_key.retiredCount(),
                    });
                } else |err| {
                    freeSealKey(g_allocator, boxed);
                    log.warn("reload: failed to publish seal key ({}), keeping previous", .{err});
                }
            } else |err| {
                key.deinit();
                log.warn("reload: failed to store seal key ({}), keeping previous", .{err});
            }
        } else |_| {
            log.warn("reload: failed to reload seal key {s}", .{key_path});
        }
    }

    _ = g_config_gen.increment();
    // Wake the workers so they reach a quiescent point and any superseded key
    // becomes reclaimable rather than accumulating.
    g_config_gen.wake();
    log.info("config generation advanced to {d}", .{g_config_gen.load()});
}

fn onWorkerReload() void {
    log.debug("worker: config reload acknowledged", .{});
}

// =============================================================================
// Tests
// =============================================================================

test {
    _ = arc;
    _ = chain;
    _ = seal;
}

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

test "results part drops the authserv-id" {
    try std.testing.expectEqualStrings(
        "spf=pass smtp.mailfrom=a.test",
        resultsPart("mail.example.org; spf=pass smtp.mailfrom=a.test").?,
    );
    try std.testing.expectEqualStrings(
        "dkim=pass header.d=a.test",
        resultsPart("  mail.example.org;  dkim=pass header.d=a.test;  ").?,
    );
    try std.testing.expect(resultsPart("mail.example.org") == null);
    try std.testing.expect(resultsPart("mail.example.org;   ") == null);
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

// A typo used to leave the mode at whatever the previous section set, silently.
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
