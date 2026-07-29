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
const auth_stamp = securemilter.auth_stamp;
const escape = securemilter.escape;
const commands = securemilter.milter.commands;
const codec = securemilter.milter.codec;
const responses = securemilter.milter.responses;
const negotiate = securemilter.milter.negotiate;
const dns_mod = securemilter.dns;
const zmq = securemilter.zmq;
const log = securemilter.log;
const header_scrub = securemilter.header_scrub;

const securemilter_crypto = @import("securemilter_crypto");
const header_select = securemilter_crypto.header_select;
const crypto = securemilter_crypto.crypto;

pub const arc = @import("arc.zig");
pub const chain = @import("chain.zig");
pub const seal = @import("seal.zig");

/// Listener modes, DNS-failure policy and the config parser.
///
/// Re-exported so an external caller keeps the names it already used, and aliased
/// below so the several dozen references in this file did not have to be rewritten
/// to move the code — a mechanical rename across a 1698-line file is exactly the
/// kind of large diff that hides a real change inside it.
pub const settings = @import("settings.zig");
const settings_test = @import("settings_test.zig");

/// Construction of the ARC set's header bytes. Aliased for the same reason as
/// `settings` above: the move should not show up as a rename at every call site.
pub const sealbuild = @import("sealbuild.zig");
const sealbuild_test = @import("sealbuild_test.zig");

/// The end-of-message flow: validate a chain, and extend it.
///
/// `flow` reads no global state. What is left here is the daemon's configuration and
/// the two functions below that snapshot it, which is why the dependency runs one way
/// only — `flow.zig` does not import this file.
pub const flow = @import("flow.zig");
const flow_test = @import("flow_test.zig");

const MsgCtx = flow.MsgCtx;
const SealCtx = flow.SealCtx;
const doVerify = flow.doVerify;
const doSeal = flow.doSeal;

const buildSigningHeaders = sealbuild.buildSigningHeaders;
const buildSealInput = sealbuild.buildSealInput;
const buildAarContent = sealbuild.buildAarContent;
const foldBase64 = sealbuild.foldBase64;

pub const Mode = settings.Mode;
pub const OnDnsError = settings.OnDnsError;
pub const ArcConfig = settings.ArcConfig;
pub const parseMode = settings.parseMode;
pub const parseOnDnsError = settings.parseOnDnsError;
pub const parseArcConfig = settings.parseArcConfig;
const modeLabel = settings.modeLabel;

const reload_mod = securemilter.reload;
const rcu_mod = securemilter.rcu;

// Restart-only state, set before worker spawn and read-only thereafter. Everything
// a SIGHUP can change lives in `g_reloadable` instead.

/// Mode per listener, index-parallel to the configured listen addresses (audit A-2).
///
/// Restart-only, and not merely unimplemented: a listener's mode is a property of an
/// open socket, and changing it under an established connection would mean a message
/// whose `connect` was accepted by a verify listener finishing as a seal. Rebinding
/// sockets is a restart by another name.
var g_modes: []const Mode = &.{};

/// ZMQ event sink. Restart-only because `tl_publisher` is a thread-local socket
/// created once per worker; adopting a new endpoint means tearing those down and
/// recreating them, which is a separate piece of work from reloading values.
var g_zmq_endpoint: ?[]const u8 = null;
var g_zmq_topic: []const u8 = "arc";

var g_allocator: Allocator = undefined;
var g_config_path: []const u8 = "/usr/local/etc/securearc/securearc.conf";
var g_health_monitor: ?*dns_mod.HealthMonitor = null;
var g_config_gen: reload_mod.ConfigGeneration = reload_mod.ConfigGeneration.init();

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

/// The reloadable configuration, published as one immutable snapshot.
///
/// One cell rather than nine, deliberately. Nine independently swapped globals
/// would let a message run against a torn configuration -- a new `authserv_id` with
/// the old `local_auth_methods`, say -- which is a worse failure than not reloading
/// at all, because it is invisible. Publishing the set atomically means a message
/// sees either the whole old configuration or the whole new one (audit A-14).
const ReloadableRcu = rcu_mod.Rcu(settings.Reloadable);
var g_reloadable: ReloadableRcu = undefined;

fn freeReloadable(allocator: Allocator, r: *settings.Reloadable) void {
    r.deinit(allocator);
    allocator.destroy(r);
}

/// Take ownership of `r` and make it the live snapshot.
///
/// Owns `r` on every path: on failure it is released here rather than left to the
/// caller, because a caller that has just been told publication failed has no way to
/// know whether the value was boxed first. That ambiguity is what X-10 was.
fn adoptReloadable(r: settings.Reloadable) !void {
    var owned = r;
    const boxed = g_allocator.create(settings.Reloadable) catch |err| {
        owned.deinit(g_allocator);
        return err;
    };
    boxed.* = owned;
    g_reloadable.publish(&g_config_gen, boxed) catch |err| {
        freeReloadable(g_allocator, boxed);
        return err;
    };
}

/// The snapshot this message runs against.
///
/// Non-null for the life of the process: `main` publishes before any listener is
/// accepting and treats a failure there as fatal, and an `Rcu` only ever replaces a
/// value, never clears it.
fn snapshot() *const settings.Reloadable {
    return g_reloadable.get().?;
}

fn freeSealKey(allocator: Allocator, key: *crypto.SigningKey) void {
    key.deinit();
    allocator.destroy(key);
}

fn boxSealKey(allocator: Allocator, key: crypto.SigningKey) !*crypto.SigningKey {
    const boxed = try allocator.create(crypto.SigningKey);
    boxed.* = key;
    return boxed;
}

// Thread-local ZMQ publisher (one socket per worker thread — ZMQ thread-safety)
threadlocal var tl_publisher: ?zmq.Publisher = null;

fn getPublisher() *zmq.Publisher {
    if (tl_publisher == null) {
        tl_publisher = zmq.Publisher.init(g_zmq_endpoint, g_zmq_topic);
    }
    return &tl_publisher.?;
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

    // Restart-only settings: bound to sockets, worker threads or the process
    // itself, so a running daemon cannot honestly change them.
    g_modes = arc_cfg.modes;
    g_zmq_endpoint = arc_cfg.zmq_endpoint;
    g_zmq_topic = arc_cfg.zmq_topic;

    // Everything a SIGHUP can adopt, as one owned snapshot. Published before any
    // listener is accepting, and fatal if it fails: a daemon with no configuration
    // to read has nothing useful to do, and continuing would mean discovering it
    // per-message instead.
    g_reloadable = ReloadableRcu.init(allocator, freeReloadable);
    adoptReloadable(try settings.Reloadable.init(allocator, arc_cfg)) catch |err| {
        log.err("failed to publish initial configuration: {}", .{err});
        return err;
    };

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
                    "body exceeds MaxBodyBytes={d} from {f}[{f}]: message will not be validated or sealed",
                    .{ conn.limits.max_body_bytes, escape.logField(peer.name), escape.logField(peer.ip) },
                );
            } else {
                log.err("body accumulation failed for {f}[{f}]: {}", .{ escape.logField(peer.name), escape.logField(peer.ip), e });
            }
        }
    };
    return @intFromEnum(responses.Code.@"continue");
}

/// Snapshot what handling one message needs.
///
/// This and `sealCtx` are the boundary between the daemon's mutable configuration and
/// a flow that reads none of it. They live here, not in `flow.zig`, because they are
/// the only things that touch these globals — putting them beside the struct
/// definitions would make the two files import each other.
fn msgCtx(cfg: *const settings.Reloadable) MsgCtx {
    return .{
        .dns_config = cfg.dns_config,
        .health_monitor = g_health_monitor,
        .min_key_bits = cfg.min_key_bits,
        .authserv_id = cfg.authserv_id,
        .publisher = getPublisher(),
    };
}

/// Snapshot the seal configuration, or null when this daemon is not configured to
/// seal — which is the one question the three guards `doSeal` used to open with were
/// each asking separately.
fn sealCtx(msg: MsgCtx, cfg: *const settings.Reloadable) ?SealCtx {
    return .{
        .msg = msg,
        .domain = cfg.seal_domain orelse return null,
        .selector = cfg.seal_selector orelse return null,
        // Acquired exactly once here. See `SealCtx.sign_key` for why that matters.
        .sign_key = g_seal_key.get() orelse return null,
        .signed_headers = cfg.signed_headers,
        .local_auth_methods = cfg.local_auth_methods,
        .on_dns_error = cfg.on_dns_error,
    };
}

fn onEom(conn: *connection_mod.Connection) u8 {
    const start_ns = std.time.nanoTimestamp();

    // One snapshot for the whole message, taken before anything reads configuration.
    // In `both` mode this means the verify and seal halves cannot disagree because a
    // reload landed between them; taken here rather than after the strip, it also
    // means the `authserv_id` used to drop forged claims is the same one the stamp
    // below asserts. Stripping first and snapshotting second left a reload able to
    // slip between the two, so this hop would remove headers under one identity and
    // then write its own under another (audit A-14).
    const cfg = snapshot();

    // Drop forged arc= claims before validating or sealing.
    _ = header_scrub.stripAuthResults(conn, cfg.authserv_id, cfg.stripPolicy());

    const mode = modeFor(conn.listener_index);
    const ctx = msgCtx(cfg);

    // `sealCtx` is only reached on a mode that seals, so a verify-only listener
    // never acquires the signing key.
    const result = switch (mode) {
        .verify_only => doVerify(conn, ctx),
        .seal_only => doSeal(conn, sealCtx(ctx, cfg)),
        .both => blk: {
            _ = doVerify(conn, ctx);
            break :blk doSeal(conn, sealCtx(ctx, cfg));
        },
    };
    const elapsed_ms = @divFloor(std.time.nanoTimestamp() - start_ns, 1_000_000);
    const queue_id = conn.macros.queue_id orelse "-";
    const client_addr = conn.macros.client_addr orelse "unknown";
    const peer = conn.getPeerDisplay();
    // The queue id, peer name and client address are attacker-influenced -- the
    // peer name comes from rDNS the sender may control -- so each is rendered as
    // a single bare token, keeping the line to one line and each value inside its
    // own field (audit X-5).
    log.info("id={f} peer={f}[{f}] client={f} listener={d} mode={s} elapsed={d}ms", .{
        escape.logField(queue_id),
        escape.logField(peer.name),
        escape.logField(peer.ip),
        escape.logField(client_addr),
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
    // parseArcConfig hands back four slices it allocated. `Reloadable` takes its
    // own copies of what it keeps, because `cfg` is freed when this function
    // returns, so these are all released here either way.
    defer {
        g_allocator.free(arc_cfg.listen_addresses);
        g_allocator.free(arc_cfg.modes);
        g_allocator.free(arc_cfg.dns_nameservers);
        g_allocator.free(arc_cfg.local_auth_methods);
    }

    // Adopt the reloadable settings. Published before the seal key so that one
    // SIGHUP cannot leave the daemon signing with a new key under an old identity;
    // if this fails the previous snapshot stays live and the key is left alone too,
    // since a half-applied reload is the failure mode worth avoiding (audit A-14).
    const fresh = settings.Reloadable.init(g_allocator, arc_cfg) catch |err| {
        log.warn("reload: failed to copy configuration ({}), keeping previous", .{err});
        _ = g_config_gen.increment();
        return;
    };
    adoptReloadable(fresh) catch |err| {
        log.warn("reload: failed to adopt configuration ({}), keeping previous", .{err});
        _ = g_config_gen.increment();
        return;
    };
    log.info("configuration reloaded from {s} ({d} awaiting reclamation)", .{
        g_config_path,
        g_reloadable.retiredCount(),
    });

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
    _ = settings;
    _ = settings_test;
    _ = sealbuild;
    _ = sealbuild_test;
    _ = flow;
    _ = flow_test;
}
