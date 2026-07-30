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

const arc = @import("arc.zig");
const chain = @import("chain.zig");
const msgfile = @import("msgfile.zig");

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

/// Convert the shared parser's fields into `arc.Header`, which is what
/// `parseArcSets` and `validateChain` take. A field-for-field copy; the two types
/// are structurally identical and `msgfile` sits below both.
fn toArcHeaders(a: Allocator, fields: []const msgfile.Field) ![]const arc.Header {
    const out = try a.alloc(arc.Header, fields.len);
    for (fields, 0..) |f, i| out[i] = .{ .name = f.name, .value = f.value };
    return out;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = process.args();
    _ = args.next();

    var path: ?[]const u8 = null;
    var nameserver: []const u8 = "127.0.0.1";
    // Exposed for the same reason securespf-check exposes it: the conformance
    // suite serves its own zone on a high port, which cannot bind 53 unprivileged.
    var port: u16 = 53;
    var min_key_bits: u32 = 1024;
    var verbose = false;

    while (args.next()) |a| {
        if (mem.eql(u8, a, "-h") or mem.eql(u8, a, "--help")) {
            cli.out(Usage);
            return;
        } else if (mem.eql(u8, a, "-f")) {
            path = args.next() orelse return cli.fatal("missing argument for -f");
        } else if (mem.eql(u8, a, "-n")) {
            nameserver = args.next() orelse return cli.fatal("missing argument for -n");
        } else if (mem.eql(u8, a, "-p")) {
            const raw = args.next() orelse return cli.fatal("missing argument for -p");
            port = std.fmt.parseInt(u16, raw, 10) catch return cli.fatal("-p must be a port number");
        } else if (mem.eql(u8, a, "-b")) {
            const raw = args.next() orelse return cli.fatal("missing argument for -b");
            min_key_bits = std.fmt.parseInt(u32, raw, 10) catch return cli.fatal("-b must be a number");
        } else if (mem.eql(u8, a, "-v")) {
            verbose = true;
        } else if (a.len > 0 and a[0] == '-') {
            return cli.fatal("unknown option (use -h for help)");
        } else {
            path = a;
        }
    }

    const msg_path = path orelse return cli.fatal("a message file is required (use -h for help)");

    const raw = std.fs.cwd().readFileAlloc(allocator, msg_path, MAX_MESSAGE_BYTES) catch |err| {
        cli.err("securearc-check: cannot read ");
        cli.err(msg_path);
        cli.err(": ");
        cli.err(@errorName(err));
        cli.err("\n");
        process.exit(2);
    };
    defer allocator.free(raw);

    var msg = msgfile.parseMessage(allocator, raw) catch return cli.fatal("out of memory parsing message");
    defer msg.deinit();

    const headers = toArcHeaders(msg.arena.allocator(), msg.fields) catch
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
        min_key_bits,
    );

    // An unevaluable chain is reported as `temperror`, distinct from `fail`.
    // A verifier that collapsed the two would be the A-12 defect, and a suite
    // run that silently accepted `fail` for a DNS outage would be scoring the
    // wrong thing.
    switch (result.evaluation) {
        .complete => cli.out(chainToString(result.status)),
        .dns_temp_error => cli.out("temperror"),
        .internal_error => cli.out("internalerror"),
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
