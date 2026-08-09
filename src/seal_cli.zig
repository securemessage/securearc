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
const deadline_mod = securemilter.deadline;
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
    \\  -r <count>         Key records to try at one selector (default: 3, max 8)
    \\  -m <ms>            Wall-clock budget for validating the existing chain
    \\                     (default: 20000, the daemon's MaxEvaluationMs; 0 disables)
    \\  -h, --help         Show this help
    \\
    \\The chain already on the message is validated first, because the cv= this host
    \\seals is a statement about it. Exit status is 0 on success, non-zero if no set
    \\could be produced.
    \\
;

pub const Args = struct {
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
    /// Already reconciled with the RFC 8301 floor by `parseArgs`, so the value
    /// reaching `chain.validateChain` can never be below it.
    min_key_bits: u32 = crypto.RFC8301_MIN_RSA_BITS,
    /// How many key records to try at one selector when validating the chain we
    /// are about to extend (A-24). Matters more here than in `securearc-check`:
    /// committing to the wrong half of a rotating pair makes this command seal
    /// `cv=fail` over a chain that was in fact intact.
    max_key_records: u8 = chain.DEFAULT_MAX_KEY_RECORDS,
    /// The daemon's MaxEvaluationMs (X-21). This tool signs its answer, so the
    /// daemon's budget must apply here or the sealed cv= could be one the
    /// daemon would never have reached in time.
    max_evaluation_ms: i64 = deadline_mod.DEFAULT_MS,
    help: bool = false,
};

pub const ParseError = error{
    UnknownOption,
    MissingValue,
    InvalidNumber,
    OutOfRange,
    MissingFile,
    MissingRequired,
};

/// Fetch the value following a flag, or set the static message and return null.
/// `flag` is comptime so the message is a folded literal, not an allocation.
fn valueAt(argv: []const []const u8, i: usize, comptime flag: []const u8, err_msg: *?[]const u8) ?[]const u8 {
    if (i >= argv.len) {
        err_msg.* = flag ++ " needs a value";
        return null;
    }
    return argv[i];
}

/// Parse the command line (excluding the program name) into `Args`.
///
/// Pure and error-returning BY DESIGN: the first version read `process.args()`
/// and exited through `cli.fatal`, which A-22 filed as untestable -- a sealer
/// whose flag handling cannot be exercised in a test is one whose regressions
/// ship. On failure `err_msg` receives a static description; `main` maps it to
/// the exit. Messages are the ones the exiting version printed.
pub fn parseArgs(argv: []const []const u8, err_msg: *?[]const u8) ParseError!Args {
    err_msg.* = null;
    var r = Args{};

    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        const a = argv[i];
        if (mem.eql(u8, a, "-h") or mem.eql(u8, a, "--help")) {
            // Returning here preserves the original's early-exit: whatever
            // followed -h was never examined.
            r.help = true;
            return r;
        } else if (mem.eql(u8, a, "-d")) {
            i += 1;
            r.domain = valueAt(argv, i, "-d", err_msg) orelse return error.MissingValue;
        } else if (mem.eql(u8, a, "-s")) {
            i += 1;
            r.selector = valueAt(argv, i, "-s", err_msg) orelse return error.MissingValue;
        } else if (mem.eql(u8, a, "-k")) {
            i += 1;
            r.key_file = valueAt(argv, i, "-k", err_msg) orelse return error.MissingValue;
        } else if (mem.eql(u8, a, "-a")) {
            i += 1;
            r.authserv_id = valueAt(argv, i, "-a", err_msg) orelse return error.MissingValue;
        } else if (mem.eql(u8, a, "--headers")) {
            i += 1;
            r.signed_headers = valueAt(argv, i, "--headers", err_msg) orelse return error.MissingValue;
        } else if (mem.eql(u8, a, "--methods")) {
            i += 1;
            r.methods_raw = valueAt(argv, i, "--methods", err_msg) orelse return error.MissingValue;
        } else if (mem.eql(u8, a, "-t")) {
            i += 1;
            const raw = valueAt(argv, i, "-t", err_msg) orelse return error.MissingValue;
            r.timestamp = std.fmt.parseInt(u64, raw, 10) catch {
                err_msg.* = "-t must be a number";
                return error.InvalidNumber;
            };
        } else if (mem.eql(u8, a, "-n")) {
            i += 1;
            r.nameserver = valueAt(argv, i, "-n", err_msg) orelse return error.MissingValue;
        } else if (mem.eql(u8, a, "-p")) {
            i += 1;
            const raw = valueAt(argv, i, "-p", err_msg) orelse return error.MissingValue;
            r.port = std.fmt.parseInt(u16, raw, 10) catch {
                err_msg.* = "-p must be a port number";
                return error.InvalidNumber;
            };
        } else if (mem.eql(u8, a, "-b")) {
            i += 1;
            const raw = valueAt(argv, i, "-b", err_msg) orelse return error.MissingValue;
            const configured = std.fmt.parseInt(u32, raw, 10) catch {
                err_msg.* = "-b must be a number";
                return error.InvalidNumber;
            };
            // Reconciled with the RFC 8301 floor here, once, so the value reaching
            // chain.validateChain below cannot validate a chain the shipped
            // securearc rejects. §3.2 is a MUST NOT for verifiers, and unlike
            // securearc-check this command does not merely report a verdict -- it
            // signs one into an ARC-Seal that every later hop is asked to trust.
            r.min_key_bits = crypto.resolveMinRsaBits(configured).bits;
        } else if (mem.eql(u8, a, "-r")) {
            i += 1;
            const raw = valueAt(argv, i, "-r", err_msg) orelse return error.MissingValue;
            r.max_key_records = std.fmt.parseInt(u8, raw, 10) catch {
                err_msg.* = "-r must be a number";
                return error.InvalidNumber;
            };
            if (r.max_key_records == 0) {
                err_msg.* = "-r must be at least 1";
                return error.OutOfRange;
            }
        } else if (mem.eql(u8, a, "-m")) {
            i += 1;
            const raw = valueAt(argv, i, "-m", err_msg) orelse return error.MissingValue;
            r.max_evaluation_ms = std.fmt.parseInt(i64, raw, 10) catch {
                err_msg.* = "-m must be a number of milliseconds";
                return error.InvalidNumber;
            };
            if (r.max_evaluation_ms < 0) {
                err_msg.* = "-m must be 0 (disabled) or a positive number of milliseconds";
                return error.OutOfRange;
            }
        } else if (a.len > 0 and a[0] == '-') {
            err_msg.* = "unknown option (use -h for help)";
            return error.UnknownOption;
        } else {
            r.file = a;
        }
    }

    // Help wins over the required-argument checks, as it always has.
    if (r.help) return r;
    if (r.file == null) {
        err_msg.* = "a message file is required (use -h for help)";
        return error.MissingFile;
    }
    if (r.domain == null) {
        err_msg.* = "-d <domain> is required";
        return error.MissingRequired;
    }
    if (r.selector == null) {
        err_msg.* = "-s <selector> is required";
        return error.MissingRequired;
    }
    if (r.key_file == null) {
        err_msg.* = "-k <keyfile> is required";
        return error.MissingRequired;
    }
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

    const argv = try process.argsAlloc(allocator);
    defer process.argsFree(allocator, argv);

    var err_msg: ?[]const u8 = null;
    const args = parseArgs(argv[1..], &err_msg) catch {
        cli.fatal(err_msg orelse "invalid arguments");
    };
    if (args.help) {
        cli.out(Usage);
        return;
    }

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
    //
    // The RFC floor rather than -b, matching main.zig: MinimumKeyBits is a policy
    // about keys *other* ADMDs publish and must not decide whether our own seal
    // key is acceptable. -b 4096 should not refuse a conformant 2048-bit signing
    // key, and -b 512 must not sign with one no verifier will ever accept.
    var key = crypto.loadRsaKeyFile(args.key_file.?, crypto.RFC8301_MIN_RSA_BITS, .require_safe) catch |err| {
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
            .{ .min_key_bits = args.min_key_bits, .max_key_records = args.max_key_records, .max_evaluation_ms = args.max_evaluation_ms },
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
            // X-21: an expired budget is the same class -- do not seal a guess.
            .deadline_exceeded => cli.fatal("cannot determine cv=: evaluation deadline exceeded while " ++
                "validating the existing chain (sealing cv=fail would be permanent)"),
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

// --- parseArgs tests (A-22) --------------------------------------------------

fn expectParseError(
    expected: ParseError,
    expected_msg: []const u8,
    argv: []const []const u8,
) !void {
    var msg: ?[]const u8 = null;
    try std.testing.expectError(expected, parseArgs(argv, &msg));
    try std.testing.expectEqualStrings(expected_msg, msg.?);
}

test "parseArgs: minimal valid invocation and defaults" {
    var msg: ?[]const u8 = null;
    const a = try parseArgs(&.{ "-d", "example.com", "-s", "arc2026", "-k", "k.pem", "m.eml" }, &msg);
    try std.testing.expectEqualStrings("m.eml", a.file.?);
    try std.testing.expectEqualStrings("example.com", a.domain.?);
    try std.testing.expectEqualStrings("arc2026", a.selector.?);
    try std.testing.expectEqualStrings("k.pem", a.key_file.?);
    try std.testing.expectEqualStrings("securearc.test", a.authserv_id);
    try std.testing.expectEqualStrings("from:to:subject:date:message-id", a.signed_headers);
    try std.testing.expect(a.methods_raw == null);
    try std.testing.expect(a.timestamp == null);
    try std.testing.expectEqual(@as(u16, 53), a.port);
    try std.testing.expectEqual(chain.DEFAULT_MAX_KEY_RECORDS, a.max_key_records);
}

test "parseArgs: every option maps to its field" {
    var msg: ?[]const u8 = null;
    const a = try parseArgs(&.{ "-d", "d.test", "-s", "sel", "-k", "k", "-a", "auth.test", "--headers", "from:to", "--methods", "spf,dkim", "-t", "1700000000", "-n", "10.0.0.9", "-p", "5353", "-b", "2048", "-r", "7", "m.eml" }, &msg);
    try std.testing.expectEqualStrings("auth.test", a.authserv_id);
    try std.testing.expectEqualStrings("from:to", a.signed_headers);
    try std.testing.expectEqualStrings("spf,dkim", a.methods_raw.?);
    try std.testing.expectEqual(@as(u64, 1700000000), a.timestamp.?);
    try std.testing.expectEqualStrings("10.0.0.9", a.nameserver);
    try std.testing.expectEqual(@as(u16, 5353), a.port);
    try std.testing.expectEqual(@as(u32, 2048), a.min_key_bits);
    try std.testing.expectEqual(@as(u8, 7), a.max_key_records);
}

test "parseArgs: -b reconciles with the RFC 8301 floor" {
    // The sealer's version of the rule is the one that matters most: it SIGNS
    // the verdict, so a flag that went below the floor would seal a verdict
    // the shipped daemon cannot reach.
    var msg: ?[]const u8 = null;
    const a = try parseArgs(&.{ "-d", "d", "-s", "s", "-k", "k", "-b", "512", "m.eml" }, &msg);
    try std.testing.expectEqual(@as(u32, crypto.RFC8301_MIN_RSA_BITS), a.min_key_bits);
}

test "parseArgs: -h short-circuits, required checks included" {
    var msg: ?[]const u8 = null;
    const a = try parseArgs(&.{"-h"}, &msg);
    try std.testing.expect(a.help);
}

test "parseArgs: required arguments are enforced in order" {
    try expectParseError(error.MissingFile, "a message file is required (use -h for help)", &.{});
    try expectParseError(error.MissingRequired, "-d <domain> is required", &.{"m.eml"});
    try expectParseError(error.MissingRequired, "-s <selector> is required", &.{ "-d", "d", "m.eml" });
    try expectParseError(error.MissingRequired, "-k <keyfile> is required", &.{ "-d", "d", "-s", "s", "m.eml" });
}

test "parseArgs: missing values, bad numbers, unknown options" {
    try expectParseError(error.MissingValue, "-d needs a value", &.{"-d"});
    try expectParseError(error.MissingValue, "--headers needs a value", &.{"--headers"});
    try expectParseError(error.InvalidNumber, "-t must be a number", &.{ "-t", "now", "m.eml" });
    try expectParseError(error.InvalidNumber, "-p must be a port number", &.{ "-p", "x", "m.eml" });
    try expectParseError(error.InvalidNumber, "-b must be a number", &.{ "-b", "x", "m.eml" });
    try expectParseError(error.InvalidNumber, "-r must be a number", &.{ "-r", "x", "m.eml" });
    try expectParseError(error.OutOfRange, "-r must be at least 1", &.{ "-r", "0", "m.eml" });
    try expectParseError(error.UnknownOption, "unknown option (use -h for help)", &.{"--seal-everything"});
}

test "parseArgs: -m maps to max_evaluation_ms, 0 disables, negatives refused" {
    var msg: ?[]const u8 = null;
    const base = [_][]const u8{ "-d", "d", "-s", "s", "-k", "k" };
    const a = try parseArgs(&(base ++ .{ "-m", "5000", "m.eml" }), &msg);
    try std.testing.expectEqual(@as(i64, 5000), a.max_evaluation_ms);

    const off = try parseArgs(&(base ++ .{ "-m", "0", "m.eml" }), &msg);
    try std.testing.expectEqual(@as(i64, 0), off.max_evaluation_ms);

    try expectParseError(error.InvalidNumber, "-m must be a number of milliseconds", &(base ++ .{ "-m", "x", "m.eml" }));
    try expectParseError(error.OutOfRange, "-m must be 0 (disabled) or a positive number of milliseconds", &(base ++ .{ "-m", "-1", "m.eml" }));
    try expectParseError(error.MissingValue, "-m needs a value", &(base ++ .{"-m"}));

    const dflt = try parseArgs(&(base ++ .{"m.eml"}), &msg);
    try std.testing.expectEqual(deadline_mod.DEFAULT_MS, dflt.max_evaluation_ms);
}
