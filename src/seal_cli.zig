//! `securearc-seal` — seal a message file with the daemon's own sealing path.
//!
//! The counterpart to `securearc-check`, and the reason it exists is the last
//! untested direction in this repository: **nothing has ever looked at a seal
//! `securearc` produced.** `securearc-check` drives the validation half of the
//! ValiMail suite, so our verifier is measured against an independent signer. The
//! signing half had no entry point at all.
//!
//! That gap is not hypothetical, and the cost of leaving it open was measured on
//! `securedkim` the same day. D-18 broke Ed25519 signing and verification
//! *symmetrically* — they round-tripped perfectly against each other, so 204
//! differential cases, 17 RFC vectors and 388 unit tests all passed while every
//! signature the daemon emitted was rejected by every conformant verifier. Reverting
//! only its signing half is caught by an external verifier in four cases and is
//! invisible to everything else. **A round-trip test agrees with a symmetric
//! mistake.**
//!
//! It calls the same `sealbuild.buildSet` the milter calls, through a real
//! `Connection`, and derives `cv` and the new instance number the same way
//! `flow.doSeal` does — so a conformance result is a statement about the shipped
//! sealer rather than about a parallel implementation written to pass tests.
//! `flow.doSeal` itself is not reused for the same reason `check.zig` cannot reuse
//! `flow.doVerify`: it wants daemon configuration and writes to a milter socket.
//!
//! Message parsing is shared with `securearc-check` via `msgfile`, deliberately, so
//! the two tools cannot drift into modelling production differently.

const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const process = std.process;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const cli = securemilter.cli.Tool("securearc-seal");
const dns_mod = securemilter.dns;
const connection_mod = securemilter.connection;

const securemilter_crypto = @import("securemilter_crypto");
const crypto = securemilter_crypto.crypto;

const msgfile = securemilter.msgfile;

const arc = @import("arc.zig");
const chain = @import("chain.zig");
const sealbuild = @import("sealbuild.zig");

const MAX_MESSAGE_BYTES = 8 * 1024 * 1024;

const Usage =
    \\Usage: securearc-seal [options] <message-file>
    \\
    \\Seal a message with the same code path the milter uses, and print the three
    \\header fields of the new ARC set to stdout, separated by blank lines:
    \\
    \\  ARC-Authentication-Results: ...
    \\
    \\  ARC-Seal: ...
    \\
    \\  ARC-Message-Signature: ...
    \\
    \\Required:
    \\  -d <domain>        Signing domain (d=)
    \\  -s <selector>      Selector (s=)
    \\  -k <file>          RSA private key, PEM
    \\
    \\Options:
    \\  -a <authserv-id>   authserv-id for the AAR, and the id whose
    \\                     Authentication-Results this host will vouch for
    \\  --headers <list>   Colon-separated h= list for the AMS
    \\                     (default: from:to:subject:date:message-id)
    \\  --methods <list>   Comma-separated local authentication methods this host
    \\                     performs. Only A-R results whose methods are all listed
    \\                     are sealed; anything else is sender-supplied and yields
    \\                     an honest "none" (RFC 8617 5.1.1)
    \\  -t <timestamp>     Signature timestamp for t= (default: now). Fix it to make
    \\                     output byte-reproducible
    \\  -n <nameserver>    DNS nameserver for validating the existing chain
    \\                     (default: 127.0.0.1)
    \\  -p <port>          DNS nameserver port (default: 53)
    \\  -b <bits>          Minimum RSA key bits accepted when validating (default: 1024)
    \\  -h, --help         Show this help
    \\
    \\The chain already on the message is validated first, because the cv= this host
    \\seals is a statement about it. Exit status is 0 on success, non-zero if no set
    \\could be produced.
    \\
;

const Args = struct {
    file: ?[]const u8 = null,
    domain: ?[]const u8 = null,
    selector: ?[]const u8 = null,
    key_file: ?[]const u8 = null,
    authserv_id: []const u8 = "securearc.test",
    signed_headers: []const u8 = "from:to:subject:date:message-id",
    methods_raw: ?[]const u8 = null,
    timestamp: ?u64 = null,
    nameserver: []const u8 = "127.0.0.1",
    port: u16 = 53,
    min_key_bits: u32 = 1024,
};

fn parseArgs() Args {
    var r = Args{};
    var it = process.args();
    _ = it.next();

    while (it.next()) |a| {
        if (mem.eql(u8, a, "-h") or mem.eql(u8, a, "--help")) {
            cli.out(Usage);
            process.exit(0);
        } else if (mem.eql(u8, a, "-d")) {
            r.domain = it.next() orelse cli.fatal("-d needs a value");
        } else if (mem.eql(u8, a, "-s")) {
            r.selector = it.next() orelse cli.fatal("-s needs a value");
        } else if (mem.eql(u8, a, "-k")) {
            r.key_file = it.next() orelse cli.fatal("-k needs a value");
        } else if (mem.eql(u8, a, "-a")) {
            r.authserv_id = it.next() orelse cli.fatal("-a needs a value");
        } else if (mem.eql(u8, a, "--headers")) {
            r.signed_headers = it.next() orelse cli.fatal("--headers needs a value");
        } else if (mem.eql(u8, a, "--methods")) {
            r.methods_raw = it.next() orelse cli.fatal("--methods needs a value");
        } else if (mem.eql(u8, a, "-t")) {
            const raw = it.next() orelse cli.fatal("-t needs a value");
            r.timestamp = std.fmt.parseInt(u64, raw, 10) catch cli.fatal("-t must be a number");
        } else if (mem.eql(u8, a, "-n")) {
            r.nameserver = it.next() orelse cli.fatal("-n needs a value");
        } else if (mem.eql(u8, a, "-p")) {
            const raw = it.next() orelse cli.fatal("-p needs a value");
            r.port = std.fmt.parseInt(u16, raw, 10) catch cli.fatal("-p must be a port number");
        } else if (mem.eql(u8, a, "-b")) {
            const raw = it.next() orelse cli.fatal("-b needs a value");
            r.min_key_bits = std.fmt.parseInt(u32, raw, 10) catch cli.fatal("-b must be a number");
        } else if (a.len > 0 and a[0] == '-') {
            cli.fatal("unknown option (use -h for help)");
        } else {
            r.file = a;
        }
    }

    if (r.file == null) cli.fatal("a message file is required (use -h for help)");
    if (r.domain == null) cli.fatal("-d <domain> is required");
    if (r.selector == null) cli.fatal("-s <selector> is required");
    if (r.key_file == null) cli.fatal("-k <keyfile> is required");
    return r;
}

/// Split a comma-separated method list. Empty input yields no methods, which makes
/// this host vouch for nothing — the honest default, not a degraded one.
fn parseMethods(a: Allocator, raw: ?[]const u8) ![]const []const u8 {
    const text = raw orelse return &.{};
    var out: std.ArrayListUnmanaged([]const u8) = .{};
    var it = mem.splitScalar(u8, text, ',');
    while (it.next()) |part| {
        const trimmed = mem.trim(u8, part, " \t");
        if (trimmed.len > 0) try out.append(a, trimmed);
    }
    return out.toOwnedSlice(a);
}

/// Field-for-field copy into `arc.Header`, which is what the chain code takes.
fn toArcHeaders(a: Allocator, fields: []const msgfile.Header) ![]const arc.Header {
    const out = try a.alloc(arc.Header, fields.len);
    for (fields, 0..) |f, i| out[i] = .{ .name = f.name, .value = f.value, .had_space = f.had_space };
    return out;
}

/// A `Connection` carrying the parsed message, because `buildSet` reads its headers
/// and body.
///
/// The pipe is not ceremony: `Connection.deinit` closes whatever descriptor it was
/// given, so handing it a fabricated number would close an unrelated file. The same
/// approach is used by `connWith` in `sealbuild.zig`, and going through a real `Connection`
/// rather than a refactored seam is what keeps this tool on the daemon's exact path.
///
/// Header names and values are duplicated because a `Connection` owns its headers
/// and frees every one — in production they are copies the milter codec made off the
/// wire.
fn connectionFor(
    allocator: Allocator,
    fd: posix.fd_t,
    fields: []const msgfile.Header,
    body: []const u8,
) !connection_mod.Connection {
    var conn = connection_mod.Connection.init(allocator, fd, 0, .{});
    errdefer conn.deinit();
    for (fields) |f| try conn.headers.append(allocator, .{
        .name = try allocator.dupe(u8, f.name),
        .value = try allocator.dupe(u8, f.value),
        .had_space = f.had_space,
    });
    try conn.appendBody(body);
    return conn;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = parseArgs();

    const raw = std.fs.cwd().readFileAlloc(allocator, args.file.?, MAX_MESSAGE_BYTES) catch
        cli.fatal("cannot read the message file");
    defer allocator.free(raw);

    var msg = msgfile.parseMessage(allocator, raw, true) catch cli.fatal("out of memory parsing the message");
    defer msg.deinit();
    const a = msg.arena.allocator();

    const headers = toArcHeaders(a, msg.headers) catch cli.fatal("out of memory");
    const local_methods = parseMethods(a, args.methods_raw) catch cli.fatal("out of memory");

    // Same standard as the daemon: this command emits real seals with a real
    // domain key, so a key anyone can read is refused here too rather than being
    // a daemon-only rule that the CLI quietly undercuts.
    var key = crypto.loadRsaKeyFile(args.key_file.?, args.min_key_bits, .require_safe) catch |err| {
        if (err == error.KeyFilePermissionsTooOpen) {
            cli.fatal("the RSA private key is readable beyond its owner; chmod 600 it");
        }
        cli.fatal("cannot load the RSA private key");
    };
    defer key.deinit();

    // The chain already present decides our cv=, so it is validated first. Mirrors
    // flow.doSeal, including that a chain which fails to PARSE is cv=fail rather
    // than cv=none (RFC 8617 §5.1.2) -- a sender must not be able to downgrade a
    // broken chain to "unsealed" by malforming it.
    var parse_failed = false;
    const sets = arc.parseArcSets(allocator, headers) catch |err| blk: {
        if (err == error.OutOfMemory) cli.fatal("out of memory parsing ARC sets");
        parse_failed = true;
        break :blk &[_]arc.ArcSet{};
    };
    defer if (!parse_failed) allocator.free(sets);

    // RFC 8617 §5.1.3, mirroring flow.doSeal: a chain an earlier hop already marked
    // cv=fail cannot be continued, so no set is produced. Empty output and exit 0 --
    // "correctly added nothing" is a success, and the ValiMail `no_additional_sig`
    // case expects exactly this.
    if (arc.chainAlreadyBroken(sets)) return;

    const new_instance: u8 = if (sets.len > 0) sets[sets.len - 1].instance + 1 else 1;
    if (new_instance > arc.MAX_INSTANCES) cli.fatal("the chain is already at the maximum instance");

    var resolver = dns_mod.Resolver.init(allocator, .{
        .nameservers = &.{args.nameserver},
        .port = args.port,
        .timeout_ms = 5000,
        .retries = 2,
    });
    defer resolver.deinit();

    const cv: arc.ChainValidation = if (parse_failed) .fail else if (sets.len == 0) .none else blk: {
        const vr = chain.validateChain(
            allocator,
            &resolver,
            sets,
            headers,
            msg.body,
            args.min_key_bits,
        );
        switch (vr.evaluation) {
            .complete => break :blk vr.status,
            // Distinguished from `fail` on purpose. Sealing cv=fail after a DNS
            // blip is permanent under RFC 8617 §5.1.2 and indistinguishable from a
            // forgery to every later hop -- audit A-12. The daemon makes this an
            // operator policy; a conformance tool has no operator, so it refuses
            // rather than inventing one and scoring the result.
            .dns_temp_error => cli.fatal("cannot determine cv=: transient DNS failure while " ++
                "validating the existing chain (sealing cv=fail would be permanent)"),
            .internal_error => cli.fatal("cannot determine cv=: internal error validating the chain"),
        }
    };

    const fds = posix.pipe2(.{ .NONBLOCK = true }) catch cli.fatal("cannot create a pipe");
    defer posix.close(fds[0]);

    var conn = connectionFor(allocator, fds[1], msg.headers, msg.body) catch
        cli.fatal("out of memory building the connection");
    defer conn.deinit();

    var failed_step: ?[]const u8 = null;
    var set = sealbuild.buildSet(&conn, .{
        .instance = new_instance,
        .cv = cv,
        .domain = args.domain.?,
        .selector = args.selector.?,
        .signed_headers = args.signed_headers,
        .authserv_id = args.authserv_id,
        .local_auth_methods = local_methods,
        .sign_key = &key,
        .prior_sets = sets,
        .timestamp = args.timestamp orelse @intCast(std.time.timestamp()),
    }, &failed_step) catch {
        cli.err("securearc-seal: sealing failed: ");
        cli.err(failed_step orelse "building the ARC set");
        cli.err("\n");
        process.exit(1);
    };
    defer set.deinit();

    // Blank-line separated, which is the interface the ValiMail signing runner
    // expects. Values may contain CRLF+TAB folds; none contains a blank line, so
    // splitting on one recovers exactly three fields.
    cli.out("ARC-Authentication-Results: ");
    cli.out(set.aar);
    cli.out("\n\n");
    cli.out("ARC-Seal: ");
    cli.out(set.seal);
    cli.out("\n\n");
    cli.out("ARC-Message-Signature: ");
    cli.out(set.ams);
    cli.out("\n");
}
