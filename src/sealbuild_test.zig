//! Tests for `sealbuild.zig`.
//!
//! Separate file per the `dns/packet_test.zig` precedent. Pulled into the test
//! build by `main.zig`.

const std = @import("std");

const sealbuild = @import("sealbuild.zig");
const resultsPart = sealbuild.resultsPart;
const foldBase64 = sealbuild.foldBase64;

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

// --- X-10: the fold must always hand back an allocation the caller owns ------
//
// It used to return its input unchanged when short enough to need no folding, so the
// result was owned on one path and borrowed on the other with nothing in the type to
// say which. Neither call site freed it, which leaked a folded RSA signature on every
// sealed message and grew RSS without bound.
//
// `std.testing.allocator` is what makes this a real check rather than a restatement:
// it fails the test if the returned slice is never freed, and it fails just as loudly
// if the `free` below is handed memory it did not allocate. One contract, both
// directions.
test "foldBase64 returns owned memory on both the folding and the short path" {
    const a = std.testing.allocator;

    // The short path. This is the one that used to borrow.
    const short = "c2hvcnQ=";
    const folded_short = try foldBase64(a, short);
    defer a.free(folded_short);
    try std.testing.expectEqualStrings(short, folded_short);
    try std.testing.expect(folded_short.ptr != short.ptr);

    // Exactly at the 76-byte boundary: still no fold, still owned.
    const at_limit = "A" ** 76;
    const folded_limit = try foldBase64(a, at_limit);
    defer a.free(folded_limit);
    try std.testing.expectEqualStrings(at_limit, folded_limit);

    // The folding path, at the length an RSA-2048 signature actually reaches, which
    // is why the leak fired on every message rather than occasionally.
    const sig_b64 = "A" ** 344;
    const folded_sig = try foldBase64(a, sig_b64);
    defer a.free(folded_sig);
    try std.testing.expect(std.mem.indexOf(u8, folded_sig, "\r\n\t") != null);
    // Four folds over 344 bytes, each inserting CRLF+TAB, and no data lost.
    try std.testing.expectEqual(sig_b64.len + 4 * 3, folded_sig.len);
}
