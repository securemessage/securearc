//! Tests for `sealbuild.zig`.
//!
//! Separate file per the `dns/packet_test.zig` precedent. Pulled into the test
//! build by `main.zig`.

const std = @import("std");

const sealbuild = @import("sealbuild.zig");
const resultsPart = sealbuild.resultsPart;

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

