//! `securearc-check` — validate the ARC chain of a message file and print the result.
//!
//! Exists so ARC chain validation can be driven by an external conformance suite
//! the way `securespf-check` lets the RFC 7208 suite drive SPF evaluation. The
//! ValiMail `arc_test_suite` is written against exactly this interface: give it a
//! message and a nameserver, get back `none`, `pass` or `fail`.
//!
//! It deliberately calls the same `arc.parseArcSets` and `chain.validateChain`
//! the milter calls, in the same order and with the same treatment of a chain
//! that fails to parse, so that a conformance result is a statement about the
//! shipped verifier rather than about a parallel implementation written to pass
//! tests. `flow.doVerify` is not reused directly only because it needs a live
//! milter `Connection`.

const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const process = std.process;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const cli = securemilter.cli.Tool("securearc-check");
const dns_mod = securemilter.dns;
const deadline_mod = securemilter.deadline;

const securemilter_crypto = @import("securemilter_crypto");
const crypto = securemilter_crypto.crypto;

const msgfile = securemilter.msgfile;

const arc = @import("arc.zig");
const chain = @import("chain.zig");

const Usage =
    \\Usage: securearc-check [options] <message-file>
    \\
    \\Validate the ARC chain of an RFC 5322 message and print the chain
    \\validation value: none, pass or fail.
    \\
    \\Options:
    \\  -f <file>        Message file (may also be given positionally)
    \\  -n <nameserver>  DNS nameserver (default: 127.0.0.1)
    \\  -p <port>        DNS nameserver port (default: 53)
    \\  -b <bits>        Minimum RSA key bits accepted (default: 1024)
    \\  -r <count>       Key records to try at one selector (default: 3, max 8)
    \\  -m <ms>          Wall-clock budget for the whole validation (default:
    \\                   20000, the daemon's MaxEvaluationMs; 0 disables)
    \\  -v               Verbose: also print the failure reason and instance count
    \\  -h               Show this help
    \\
    \\Exit status is 0 whenever a verdict was reached, including "fail" — the
    \\verdict goes to stdout. A non-zero status means the tool could not run.
    \\
;

/// Largest message accepted. Generous for a conformance suite whose cases are a
/// few kilobytes, and bounded so a stray argument cannot exhaust memory.
const MAX_MESSAGE_BYTES = 8 * 1024 * 1024;

pub const Args = struct {
    path: ?[]const u8 = null,
    nameserver: []const u8 = "127.0.0.1",
    // Exposed for the same reason securespf-check exposes it: the conformance
    // suite serves its own zone on a high port, which cannot bind 53 unprivileged.
    port: u16 = 53,
    min_key_bits: u32 = 1024,
    // Exposed so this tool can reproduce a key-rotation verdict the daemon would
    // reach (A-24). A -check tool that could not vary this would answer a
    // different question from the one the operator is asking.
    max_key_records: u8 = chain.DEFAULT_MAX_KEY_RECORDS,
    /// The daemon's MaxEvaluationMs, on the CLI for the same reason -b and -r
    /// are: the tool must answer the question the daemon answers (X-21).
    max_evaluation_ms: i64 = deadline_mod.DEFAULT_MS,
    verbose: bool = false,
    help: bool = false,
};

pub const ParseError = error{
    UnknownOption,
    MissingValue,
    InvalidNumber,
    OutOfRange,
    MissingFile,
};

/// Fetch the value following a flag, or set the static message and return null.
/// `flag` is comptime so the message is a folded literal, not an allocation.
fn valueAt(argv: []const []const u8, i: usize, comptime flag: []const u8, err_msg: *?[]const u8) ?[]const u8 {
    if (i >= argv.len) {
        err_msg.* = "missing argument for " ++ flag;
        return null;
    }
    return argv[i];
}

/// Parse the command line (excluding the program name) into `Args`.
///
/// Pure and error-returning BY DESIGN: the first version of this loop lived
/// inline in `main`, reading `process.args()` and exiting through `cli.fatal`,
/// which A-22 filed as untestable by construction -- a CLI whose flag handling
/// cannot be exercised in a test is a CLI whose regressions are found by the
/// conformance suite or by nobody. On failure `err_msg` receives a static
/// description of which flag failed and why; `main` maps that to the exit.
pub fn parseArgs(argv: []const []const u8, err_msg: *?[]const u8) ParseError!Args {
    err_msg.* = null;
    var r = Args{};

    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        const a = argv[i];
        if (mem.eql(u8, a, "-h") or mem.eql(u8, a, "--help")) {
            // The pre-refactor loop printed usage and returned AT this point,
            // so anything after -h was never examined. Returning here keeps
            // that exact shape.
            r.help = true;
            return r;
        } else if (mem.eql(u8, a, "-f")) {
            i += 1;
            r.path = valueAt(argv, i, "-f", err_msg) orelse return error.MissingValue;
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
            // Reconciled with the RFC 8301 floor, exactly as the daemon does via
            // settings.zig and as `securedkim-check` already did here (A-22).
            // Without this, `-b 512` made this tool accept a chain the shipped
            // `securearc` rejects -- and the only purpose of a -check tool is to
            // report the verdict the daemon would reach. RFC 8301 3.2 is a MUST
            // NOT for verifiers, so one command-line flag should not re-admit
            // signatures the standard says have permanently failed.
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
        } else if (mem.eql(u8, a, "-v")) {
            r.verbose = true;
        } else if (a.len > 0 and a[0] == '-') {
            err_msg.* = "unknown option (use -h for help)";
            return error.UnknownOption;
        } else {
            r.path = a;
        }
    }

    // Help wins over the required-argument check, as it always has: `-h` with no
    // message file must print usage, not an error.
    if (r.help) return r;
    if (r.path == null) {
        err_msg.* = "a message file is required (use -h for help)";
        return error.MissingFile;
    }
    return r;
}

/// Convert the shared parser's fields into `arc.Header`, which is what
/// `parseArcSets` and `validateChain` take. A field-for-field copy, `had_space`
/// included -- the bit exists so `c=simple` can rebuild the field verbatim, and a
/// copy that drops it fails silently.
fn toArcHeaders(a: Allocator, fields: []const msgfile.Header) ![]const arc.Header {
    const out = try a.alloc(arc.Header, fields.len);
    for (fields, 0..) |f, i| out[i] = .{ .name = f.name, .value = f.value, .had_space = f.had_space };
    return out;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const argv = try process.argsAlloc(allocator);
    defer process.argsFree(allocator, argv);

    var err_msg: ?[]const u8 = null;
    const opts = parseArgs(argv[1..], &err_msg) catch {
        cli.fatal(err_msg orelse "invalid arguments");
    };
    if (opts.help) {
        cli.out(Usage);
        return;
    }

    const msg_path = opts.path.?;
    const nameserver = opts.nameserver;
    const port = opts.port;
    const min_key_bits = opts.min_key_bits;
    const max_key_records = opts.max_key_records;
    const max_evaluation_ms = opts.max_evaluation_ms;
    const verbose = opts.verbose;

    const raw = std.fs.cwd().readFileAlloc(allocator, msg_path, MAX_MESSAGE_BYTES) catch |err| {
        cli.err("securearc-check: cannot read ");
        cli.err(msg_path);
        cli.err(": ");
        cli.err(@errorName(err));
        cli.err("\n");
        process.exit(2);
    };
    defer allocator.free(raw);

    var msg = msgfile.parseMessage(allocator, raw, true) catch return cli.fatal("out of memory parsing message");
    defer msg.deinit();

    const headers = toArcHeaders(msg.arena.allocator(), msg.headers) catch
        return cli.fatal("out of memory converting headers");

    const ns_slice: []const []const u8 = &.{nameserver};
    var resolver = dns_mod.Resolver.init(allocator, .{
        .nameservers = ns_slice,
        .port = port,
        .timeout_ms = 5000,
        .retries = 2,
    });
    defer resolver.deinit();

    // Mirror flow.doVerify exactly, including the order of these three cases.
    //
    // A chain that fails to parse is `fail`, not `none` (RFC 8617 §5.1.2): a
    // sender that could downgrade a broken chain to "unsealed" by malforming it
    // would defeat the point of the chain. The conformance suite tests that
    // distinction directly, which is why the check tool must not simplify it.
    const sets = arc.parseArcSets(allocator, headers) catch |err| {
        if (err == error.OutOfMemory) return cli.fatal("out of memory parsing ARC sets");
        cli.out("fail");
        if (verbose) {
            cli.out(" reason=");
            cli.out(arc.describeChainError(err));
        }
        cli.out("\n");
        return;
    };
    defer allocator.free(sets);

    if (sets.len == 0) {
        cli.out("none\n");
        return;
    }

    const result = chain.validateChain(
        allocator,
        &resolver,
        sets,
        headers,
        msg.body,
        .{ .min_key_bits = min_key_bits, .max_key_records = max_key_records, .max_evaluation_ms = max_evaluation_ms },
    );

    // An unevaluable chain is reported as `temperror`, distinct from `fail`.
    // A verifier that collapsed the two would be the A-12 defect, and a suite
    // run that silently accepted `fail` for a DNS outage would be scoring the
    // wrong thing.
    switch (result.evaluation) {
        .complete => cli.out(chainToString(result.status)),
        .dns_temp_error => cli.out("temperror"),
        .internal_error => cli.out("internalerror"),
        // X-21: the budget answer is the retryable one, same as a DNS blip.
        .deadline_exceeded => cli.out("temperror"),
    }
    if (verbose) {
        var buf: [256]u8 = undefined;
        const extra = std.fmt.bufPrint(&buf, " i={d} reason={s}", .{
            result.highest_instance,
            result.failure_reason orelse "-",
        }) catch " (detail unavailable)";
        cli.out(extra);
    }
    cli.out("\n");
}

/// `unknown` is deliberately given its own token rather than being folded into
/// one of the three cv values. It means "no determination was made", and
/// `validateChain` only pairs it with a non-`complete` evaluation — so seeing it
/// here would be an invariant violation, not a verdict. Printing something the
/// suite cannot match makes that loud instead of scoring it as a pass or a fail.
fn chainToString(v: arc.ChainValidation) []const u8 {
    return switch (v) {
        .none => "none",
        .pass => "pass",
        .fail => "fail",
        .unknown => "unknown",
    };
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

test "parseArgs: defaults and a positional message file" {
    var msg: ?[]const u8 = null;
    const a = try parseArgs(&.{"msg.eml"}, &msg);
    try std.testing.expectEqualStrings("msg.eml", a.path.?);
    try std.testing.expectEqualStrings("127.0.0.1", a.nameserver);
    try std.testing.expectEqual(@as(u16, 53), a.port);
    try std.testing.expectEqual(@as(u32, 1024), a.min_key_bits);
    try std.testing.expectEqual(chain.DEFAULT_MAX_KEY_RECORDS, a.max_key_records);
    try std.testing.expect(!a.verbose);
    try std.testing.expect(!a.help);
}

test "parseArgs: every flag maps to its field" {
    var msg: ?[]const u8 = null;
    const a = try parseArgs(&.{ "-f", "a.eml", "-n", "10.0.0.9", "-p", "5353", "-b", "2048", "-r", "5", "-v" }, &msg);
    try std.testing.expectEqualStrings("a.eml", a.path.?);
    try std.testing.expectEqualStrings("10.0.0.9", a.nameserver);
    try std.testing.expectEqual(@as(u16, 5353), a.port);
    try std.testing.expectEqual(@as(u32, 2048), a.min_key_bits);
    try std.testing.expectEqual(@as(u8, 5), a.max_key_records);
    try std.testing.expect(a.verbose);
}

test "parseArgs: -b reconciles with the RFC 8301 floor instead of trusting the operator" {
    // A-22/A-23's rule: a -check tool must answer the question the DAEMON
    // answers, and the daemon cannot go below the floor.
    var msg: ?[]const u8 = null;
    const a = try parseArgs(&.{ "-b", "512", "m.eml" }, &msg);
    try std.testing.expectEqual(@as(u32, crypto.RFC8301_MIN_RSA_BITS), a.min_key_bits);
}

test "parseArgs: -h needs no message file" {
    var msg: ?[]const u8 = null;
    const a = try parseArgs(&.{"-h"}, &msg);
    try std.testing.expect(a.help);
    try std.testing.expect(a.path == null);
}

test "parseArgs: missing message file is an error with its message" {
    try expectParseError(error.MissingFile, "a message file is required (use -h for help)", &.{});
}

test "parseArgs: missing flag values name the flag" {
    try expectParseError(error.MissingValue, "missing argument for -f", &.{"-f"});
    try expectParseError(error.MissingValue, "missing argument for -n", &.{"-n"});
    try expectParseError(error.MissingValue, "missing argument for -p", &.{"-p"});
    try expectParseError(error.MissingValue, "missing argument for -b", &.{"-b"});
    try expectParseError(error.MissingValue, "missing argument for -r", &.{"-r"});
}

test "parseArgs: bad numbers and ranges" {
    try expectParseError(error.InvalidNumber, "-p must be a port number", &.{ "-p", "fifty-three", "m.eml" });
    try expectParseError(error.InvalidNumber, "-b must be a number", &.{ "-b", "big", "m.eml" });
    try expectParseError(error.InvalidNumber, "-r must be a number", &.{ "-r", "x", "m.eml" });
    try expectParseError(error.OutOfRange, "-r must be at least 1", &.{ "-r", "0", "m.eml" });
}

test "parseArgs: unknown options are rejected" {
    try expectParseError(error.UnknownOption, "unknown option (use -h for help)", &.{"--frobnicate"});
}

test "parseArgs: -m maps to max_evaluation_ms, 0 disables, negatives refused" {
    var msg: ?[]const u8 = null;
    const a = try parseArgs(&.{ "-m", "5000", "m.eml" }, &msg);
    try std.testing.expectEqual(@as(i64, 5000), a.max_evaluation_ms);

    const off = try parseArgs(&.{ "-m", "0", "m.eml" }, &msg);
    try std.testing.expectEqual(@as(i64, 0), off.max_evaluation_ms);

    try expectParseError(error.InvalidNumber, "-m must be a number of milliseconds", &.{ "-m", "soon", "m.eml" });
    try expectParseError(error.OutOfRange, "-m must be 0 (disabled) or a positive number of milliseconds", &.{ "-m", "-1", "m.eml" });
    try expectParseError(error.MissingValue, "missing argument for -m", &.{"-m"});

    const dflt = try parseArgs(&.{"m.eml"}, &msg);
    try std.testing.expectEqual(deadline_mod.DEFAULT_MS, dflt.max_evaluation_ms);
}
