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
    mode: Mode,
    seal_domain: ?[]const u8,
    seal_selector: ?[]const u8,
    seal_key_file: ?[]const u8,
    signed_headers: []const u8,
    zmq_endpoint: ?[]const u8,
    zmq_topic: []const u8,
};

const reload_mod = securemilter.reload;

// Module-level config set before worker spawn, read-only during runtime.
var g_authserv_id: []const u8 = "localhost";
var g_dns_config: dns_mod.ResolverConfig = .{};
var g_mode: Mode = .verify_only;
var g_seal_domain: ?[]const u8 = null;
var g_seal_selector: ?[]const u8 = null;
var g_seal_key: ?crypto.SigningKey = null;
var g_signed_headers: []const u8 = "from:to:subject:date:message-id";
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

    var addrs: std.ArrayListUnmanaged(listener_mod.ListenAddress) = .{};
    errdefer addrs.deinit(allocator);

    var mode: Mode = .verify_only;
    var seal_domain: ?[]const u8 = null;
    var seal_selector: ?[]const u8 = null;
    var seal_key_file: ?[]const u8 = null;

    for (cfg.section_order.items) |section_name| {
        if (mem.startsWith(u8, section_name, "listener:")) {
            const section = cfg.getSection(section_name) orelse continue;
            const socket_str = section.get("Socket") orelse continue;
            const addr = listener_mod.ListenAddress.parse(socket_str) catch continue;
            try addrs.append(allocator, addr);

            if (section.get("Mode")) |mode_str| {
                if (mem.eql(u8, mode_str, "seal")) mode = .seal_only else if (mem.eql(u8, mode_str, "verify")) mode = .verify_only else if (mem.eql(u8, mode_str, "both")) mode = .both;
            }

            seal_domain = section.get("SealDomain") orelse seal_domain;
            seal_selector = section.get("SealSelector") orelse seal_selector;
            seal_key_file = section.get("SealKeyFile") orelse seal_key_file;
        }
    }

    if (addrs.items.len == 0) {
        try addrs.append(allocator, .{ .tcp = .{ .host = "0.0.0.0", .port = 8895 } });
    }

    // Global-level seal config (overridden by per-listener)
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
    const dns_timeout = global.getInt("DnsTimeout", u32, 5) * 1000;
    const dns_retries = global.getInt("DnsRetries", u8, 2);
    const signed_headers = global.getOrDefault("SignedHeaders", "from:to:subject:date:message-id");
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
        .mode = mode,
        .seal_domain = seal_domain,
        .seal_selector = seal_selector,
        .seal_key_file = seal_key_file,
        .signed_headers = signed_headers,
        .zmq_endpoint = zmq_endpoint,
        .zmq_topic = zmq_topic,
    };
}

fn usageError() error{InvalidArgument} {
    std.log.err("usage: securearc -c <config-file>", .{});
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
        std.log.err("failed to load config {s}: {}", .{ config_path, err });
        return err;
    };
    defer cfg.deinit();

    const arc_cfg = parseArcConfig(allocator, &cfg) catch |err| {
        std.log.err("config parse error: {}", .{err});
        return err;
    };

    // Set module-level globals
    g_authserv_id = arc_cfg.authserv_id;
    g_dns_config = .{
        .nameservers = arc_cfg.dns_nameservers,
        .timeout_ms = arc_cfg.dns_timeout_ms,
        .retries = arc_cfg.dns_retries,
    };

    g_mode = arc_cfg.mode;
    g_seal_domain = arc_cfg.seal_domain;
    g_seal_selector = arc_cfg.seal_selector;
    g_signed_headers = arc_cfg.signed_headers;
    g_zmq_endpoint = arc_cfg.zmq_endpoint;
    g_zmq_topic = arc_cfg.zmq_topic;

    // Load seal key if configured
    if (arc_cfg.seal_key_file) |key_path| {
        g_seal_key = crypto.loadRsaKeyFile(key_path) catch |err| {
            std.log.err("failed to load seal key {s}: {}", .{ key_path, err });
            return err;
        };
    }

    // Daemonize — MUST happen before spawning any threads (fork only preserves calling thread)
    if (!arc_cfg.foreground) {
        daemon_mod.daemonize() catch |err| {
            std.log.err("daemonize failed: {}", .{err});
            return err;
        };
    }

    // Start proactive DNS health monitor AFTER daemonize
    if (dns_mod.HealthMonitor.init(allocator, arc_cfg.dns_nameservers, 53, 5, 2000)) |monitor| {
        monitor.start() catch |err| {
            std.log.warn("DNS health monitor thread failed: {}", .{err});
        };
        g_health_monitor = monitor;
    } else |err| {
        std.log.warn("DNS health monitor init failed: {}, falling back to reactive", .{err});
    }

    daemon_mod.writePidFile(arc_cfg.pid_file) catch |err| {
        std.log.err("pid file write failed: {}", .{err});
    };
    defer daemon_mod.removePidFile(arc_cfg.pid_file);

    // Raise fd limit to calculated budget before dropping privileges
    const num_workers = if (arc_cfg.worker_threads == 0) @as(u32, @intCast(std.Thread.getCpuCount() catch 4)) else arc_cfg.worker_threads;
    const fd_need = daemon_mod.calculateFdNeed(num_workers, worker_mod.DEFAULT_MAX_CONNECTIONS, @intCast(arc_cfg.listen_addresses.len));
    daemon_mod.raiseFileLimit(fd_need);

    // Drop privileges after PID file is written, before workers spawn
    if (arc_cfg.user) |user| {
        daemon_mod.dropPrivileges(user) catch |err| {
            std.log.err("privilege drop to '{s}' failed: {}", .{ user, err });
            return err;
        };
    }

    std.log.info("SecureARC starting, AuthservID={s}, mode={s}, listeners={d}", .{
        arc_cfg.authserv_id,
        @tagName(arc_cfg.mode),
        arc_cfg.listen_addresses.len,
    });

    const required_actions = negotiate.ActionFlags{ .add_headers = true };

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
    };

    const shutdown_pipe = try posix.pipe();
    defer posix.close(shutdown_pipe[0]);

    daemon_mod.ManagedSignals.blockForKqueue();

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
    conn.appendBody(data) catch {};
    return @intFromEnum(responses.Code.@"continue");
}

fn onEom(conn: *connection_mod.Connection) u8 {
    switch (g_mode) {
        .verify_only => return doVerify(conn),
        .seal_only => return doSeal(conn),
        .both => {
            _ = doVerify(conn);
            return doSeal(conn);
        },
    }
}

fn doVerify(conn: *connection_mod.Connection) u8 {
    // Build header list in arc.Header format
    var arc_headers: std.ArrayListUnmanaged(arc.Header) = .{};
    defer arc_headers.deinit(conn.allocator);

    for (conn.headers.items) |hdr| {
        arc_headers.append(conn.allocator, .{ .name = hdr.name, .value = hdr.value }) catch continue;
    }

    // Parse ARC sets from headers
    const sets = arc.parseArcSets(conn.allocator, arc_headers.items) catch {
        addArHeaderSimple(conn, "arc", "none", "parse error");
        return @intFromEnum(responses.Code.@"continue");
    };
    defer conn.allocator.free(sets);

    if (sets.len == 0) {
        addArHeaderSimple(conn, "arc", "none", null);
        publishEvent(conn.allocator, "verify", "none", 0);
        return @intFromEnum(responses.Code.@"continue");
    }

    // Validate chain
    const body_data = conn.getBody();
    var resolver = dns_mod.Resolver.initWithMonitor(conn.allocator, g_dns_config, g_health_monitor);
    defer resolver.deinit();

    const result = chain.validateChain(
        conn.allocator,
        &resolver,
        sets,
        arc_headers.items,
        body_data,
    );

    addArHeaderSimple(conn, "arc", result.status.toString(), result.failure_reason);
    publishEvent(conn.allocator, "verify", result.status.toString(), result.highest_instance);
    return @intFromEnum(responses.Code.@"continue");
}

fn doSeal(conn: *connection_mod.Connection) u8 {
    const domain = g_seal_domain orelse return @intFromEnum(responses.Code.@"continue");
    const selector = g_seal_selector orelse return @intFromEnum(responses.Code.@"continue");
    _ = g_seal_key orelse return @intFromEnum(responses.Code.@"continue");

    // Determine instance number: count existing ARC sets + 1
    var arc_headers: std.ArrayListUnmanaged(arc.Header) = .{};
    defer arc_headers.deinit(conn.allocator);

    for (conn.headers.items) |hdr| {
        arc_headers.append(conn.allocator, .{ .name = hdr.name, .value = hdr.value }) catch continue;
    }

    const sets = arc.parseArcSets(conn.allocator, arc_headers.items) catch
        return @intFromEnum(responses.Code.@"continue");
    defer conn.allocator.free(sets);

    const new_instance: u8 = if (sets.len > 0) sets[sets.len - 1].instance + 1 else 1;
    if (new_instance > arc.MAX_INSTANCES) return @intFromEnum(responses.Code.@"continue");

    // Determine chain status for our seal
    const cv: arc.ChainValidation = if (sets.len == 0) .none else blk: {
        const body_data = conn.getBody();
        var resolver = dns_mod.Resolver.initWithMonitor(conn.allocator, g_dns_config, g_health_monitor);
        defer resolver.deinit();
        const vr = chain.validateChain(conn.allocator, &resolver, sets, arc_headers.items, body_data);
        break :blk vr.status;
    };

    // Build AAR content from existing A-R headers matching our authserv-id
    const ar_content = buildAarContent(conn) orelse "none";

    // Build ARC-Authentication-Results header and prepend
    const aar = std.fmt.allocPrint(conn.allocator, "i={d}; {s}", .{ new_instance, ar_content }) catch
        return @intFromEnum(responses.Code.@"continue");
    defer conn.allocator.free(aar);

    prependHeader(conn, "ARC-Authentication-Results", aar);

    // Build AMS: sign the message (same as DKIM signing)
    const body_data = conn.getBody();
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
    const sign_key = &g_seal_key.?;
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

fn buildAarContent(conn: *connection_mod.Connection) ?[]const u8 {
    for (conn.headers.items) |hdr| {
        if (eqlIgnoreCase(hdr.name, "Authentication-Results")) {
            if (auth_results.matchesAuthservId(hdr.value, g_authserv_id)) {
                return hdr.value;
            }
        }
    }
    return null;
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
        std.log.warn("reload: failed to re-read config file, keeping previous", .{});
        g_config_gen.increment();
        return;
    };
    defer cfg.deinit();

    const arc_cfg = parseArcConfig(g_allocator, &cfg) catch {
        std.log.warn("reload: failed to parse config, keeping previous", .{});
        g_config_gen.increment();
        return;
    };

    if (arc_cfg.seal_key_file) |key_path| {
        if (crypto.loadRsaKeyFile(key_path)) |new_key| {
            g_seal_key = new_key;
            std.log.info("seal key reloaded from {s}", .{key_path});
        } else |_| {
            std.log.warn("reload: failed to reload seal key {s}", .{key_path});
        }
    }

    g_config_gen.increment();
    std.log.info("config generation advanced to {d}", .{g_config_gen.load()});
}

fn onWorkerReload() void {
    std.log.debug("worker: config reload acknowledged", .{});
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

    try std.testing.expectEqualStrings("mail.test.com", arc_cfg.authserv_id);
    try std.testing.expectEqual(@as(usize, 1), arc_cfg.listen_addresses.len);
    try std.testing.expectEqual(Mode.verify_only, arc_cfg.mode);
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

    try std.testing.expectEqual(Mode.seal_only, arc_cfg.mode);
    try std.testing.expectEqualStrings("test.com", arc_cfg.seal_domain.?);
    try std.testing.expectEqualStrings("arc2026", arc_cfg.seal_selector.?);
}
