//! Tests for the end-of-message flow.
//!
//! Separate file per the `sealbuild_test.zig` and `dns/packet_test.zig` precedent, so
//! neither the flow nor its tests is counted against the other's length. Symbols are
//! aliased below so no test body needed editing when these moved out of `main.zig`.

const std = @import("std");
const posix = std.posix;
const mem = std.mem;

const flow = @import("flow.zig");
const emitArcSet = flow.emitArcSet;
const addArHeaderSimple = flow.addArHeaderSimple;

// --- X-8: a partial ARC set must never reach the wire ------------------------

test "emitArcSet writes the whole set or nothing, at every failure point" {
    // The harmful state is a *partial* set. RFC 8617 requires all three headers
    // per instance, so AAR alone, or AAR+AMS with no ARC-Seal, is a malformed
    // chain: the next hop records cv=fail and 5.1.2 makes that permanent. Our own
    // allocation failure would then destroy a chain that may be perfectly valid.
    //
    // Stated as a property over every allocation the function performs rather
    // than against a hand-picked fail index, so it cannot rot as the number of
    // allocations inside addHeader changes.
    var fail_index: usize = 0;
    var saw_success = false;
    var saw_failure = false;
    while (fail_index < 16) : (fail_index += 1) {
        const fds = try posix.pipe2(.{ .NONBLOCK = true });
        defer posix.close(fds[0]);
        defer posix.close(fds[1]);

        var failing = std.testing.FailingAllocator.init(
            std.testing.allocator,
            .{ .fail_index = fail_index },
        );
        const res = emitArcSet(
            failing.allocator(),
            fds[1],
            "i=1; mail.test; spf=pass",
            "i=1; a=rsa-sha256; b=AAAA",
            "i=1; cv=none; a=rsa-sha256; b=BBBB",
        );

        var buf: [1024]u8 = undefined;
        const n = posix.read(fds[0], &buf) catch |err| switch (err) {
            error.WouldBlock => 0,
            else => return err,
        };

        if (res) |_| {
            saw_success = true;
            // All three present, seal first on the wire.
            //
            // THIS ASSERTION USED TO BE REVERSED, and its comment explained why:
            // "in the order that makes the message read ARC-Seal, AMS, AAR downward
            // once each prepend is applied". `addHeader` builds SMFIR_ADDHEADER,
            // which appends -- nothing prepends -- so writing AAR first delivered
            // AAR first, the reverse of the stated intent. The test asserted the
            // write order and agreed with the code, so both were wrong together and
            // neither could catch the other (audit A-8).
            //
            // Wire order is now the delivered top-down order: AS, AMS, AAR, matching
            // OpenARC and RFC 8617's example messages. Not a conformance property --
            // §5 calls relative trace-field order "unimportant" -- so this pins a
            // convention, and pins that the mechanism still matches the intent.
            const aar_at = mem.indexOf(u8, buf[0..n], "ARC-Authentication-Results") orelse
                return error.TestUnexpectedResult;
            const ams_at = mem.indexOf(u8, buf[0..n], "ARC-Message-Signature") orelse
                return error.TestUnexpectedResult;
            const seal_at = mem.indexOf(u8, buf[0..n], "ARC-Seal") orelse
                return error.TestUnexpectedResult;
            try std.testing.expect(seal_at < ams_at);
            try std.testing.expect(ams_at < aar_at);
        } else |_| {
            saw_failure = true;
            // The message must be untouched. Before X-8 was fixed, headers were
            // built and written where they were computed, so a failure here left
            // one or two of the three on the wire and this read returned bytes.
            try std.testing.expectEqual(@as(usize, 0), n);
        }
    }

    // Guard against the test passing because it exercised nothing: the range must
    // cover both a failing allocation and the fully successful case.
    try std.testing.expect(saw_failure);
    try std.testing.expect(saw_success);
}

// X-9: this wrapper must stay fallible.
//
// It returned `void` and swallowed all three failure points, so a message could
// be delivered with no `arc=` field while this daemon reported success. On a
// verify listener that field is the only record of what this hop concluded about
// the chain, and no later hop can reconstruct it: each AMS covers content as it
// was here, so once the message moves on the evidence is gone.
test "the Authentication-Results wrapper cannot swallow failures" {
    comptime {
        const ret = @typeInfo(@TypeOf(addArHeaderSimple)).@"fn".return_type.?;
        if (@typeInfo(ret) != .error_union) @compileError(
            "addArHeaderSimple must return an error union. Swallowing a stamping failure " ++
                "delivers the message with no arc= field while reporting success, and no " ++
                "later hop can reconstruct it: each AMS covers content as it was here " ++
                "(audit X-9).",
        );
        if (@typeInfo(ret).error_union.payload != void) @compileError(
            "addArHeaderSimple should return !void; the caller maps the error to a tempfail.",
        );
    }
}
