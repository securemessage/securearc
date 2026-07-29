//! Tests for `sealbuild.zig`.
//!
//! Separate file per the `dns/packet_test.zig` precedent. Pulled into the test
//! build by `main.zig`.

const std = @import("std");
const posix = std.posix;

const securemilter = @import("securemilter");
const connection_mod = securemilter.connection;

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

// --- X-11: the fold must always hand back an allocation the caller owns ------
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

// --- The AAR trust rule (RFC 8617 §5.1.1) ------------------------------------
//
// This is a security boundary and it had no direct test. `buildAarContent` decides
// which Authentication-Results headers this ADMD is willing to vouch for
// cryptographically, and everything it accepts gets sealed into the chain under our
// domain's signature. Until the seal path was parameterised the rule was reachable
// only through a live daemon with a signing key, a resolver and a socket, so it was
// exercised end to end by the `a3` lab probe and not at all by anything cheaper.
// Being able to write these six tests is the reason the extraction was worth doing.
//
// An A-R header on an inbound message is attacker-controlled. Copying one we did not
// produce would have this host sign an assertion it never made -- the mail equivalent
// of countersigning a stranger's affidavit.

/// A connection carrying `hdrs` and nothing else.
///
/// `buildAarContent` reads `conn.headers` and allocates from `conn.allocator`; it
/// never touches the fd. The pipe exists because `Connection.deinit` closes whatever
/// it was given, and handing it a fabricated descriptor would close an unrelated file.
///
/// Names and values are duplicated because a `Connection` owns its headers -- it
/// frees every one in `deinit`, since in production they are copies the milter codec
/// made off the wire. Appending literals segfaults there, which is the invariant
/// stating itself. Duping also means these tests exercise the same ownership the
/// daemon has rather than a convenient fiction.
fn connWith(fd: posix.fd_t, hdrs: []const connection_mod.Header) !connection_mod.Connection {
    var conn = connection_mod.Connection.init(std.testing.allocator, fd, 0, .{});
    for (hdrs) |h| try conn.headers.append(std.testing.allocator, .{
        .name = try std.testing.allocator.dupe(u8, h.name),
        .value = try std.testing.allocator.dupe(u8, h.value),
    });
    return conn;
}

const our_id = "mail.relay.test";

test "an A-R claiming a different authserv-id is never vouched for" {
    const fds = try posix.pipe2(.{ .NONBLOCK = true });
    defer posix.close(fds[0]);

    // The attacker's own hostname in the authserv-id. Trivially forgeable, and the
    // only thing distinguishing it from ours is the string.
    var conn = try connWith(fds[1], &.{
        .{ .name = "Authentication-Results", .value = "mail.attacker.test; dkim=pass header.d=bank.example" },
    });
    defer conn.deinit();

    const out = sealbuild.buildAarContent(&conn, our_id, &.{"dkim"}).?;
    defer std.testing.allocator.free(out);

    // `none`, not the attacker's claim, and specifically not `dkim=pass` for a bank.
    try std.testing.expectEqualStrings("mail.relay.test; none", out);
}

test "an A-R claiming our authserv-id but a method we do not perform is rejected" {
    const fds = try posix.pipe2(.{ .NONBLOCK = true });
    defer posix.close(fds[0]);

    // Guessing our authserv-id is easy -- it is in every message we stamp. So the
    // id alone cannot be the test; what saves us is that we know which methods we
    // actually run. This host does SPF only.
    var conn = try connWith(fds[1], &.{
        .{ .name = "Authentication-Results", .value = "mail.relay.test; dkim=pass header.d=bank.example" },
    });
    defer conn.deinit();

    const out = sealbuild.buildAarContent(&conn, our_id, &.{"spf"}).?;
    defer std.testing.allocator.free(out);

    try std.testing.expectEqualStrings("mail.relay.test; none", out);
}

test "one non-local method rejects the whole header rather than being filtered out" {
    const fds = try posix.pipe2(.{ .NONBLOCK = true });
    defer posix.close(fds[0]);

    // A header mixing a method we do run with one we do not. Salvaging the spf=pass
    // and dropping the dkim=pass would be the tempting behaviour and the wrong one:
    // we would be sealing a partial copy of a header we did not write, and the
    // sender chose its contents. Reject entire.
    var conn = try connWith(fds[1], &.{
        .{ .name = "Authentication-Results", .value = "mail.relay.test; spf=pass smtp.mailfrom=ok.test; dkim=pass header.d=bank.example" },
    });
    defer conn.deinit();

    const out = sealbuild.buildAarContent(&conn, our_id, &.{"spf"}).?;
    defer std.testing.allocator.free(out);

    try std.testing.expectEqualStrings("mail.relay.test; none", out);
    try std.testing.expect(std.mem.indexOf(u8, out, "dkim") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "spf") == null);
}

test "a host that lists no local methods seals an honest none" {
    const fds = try posix.pipe2(.{ .NONBLOCK = true });
    defer posix.close(fds[0]);

    // Documented behaviour, and worth pinning because the failure mode is silent:
    // a misconfiguration that empties LocalAuthMethods must degrade to vouching for
    // nothing, never to vouching for whatever arrived.
    var conn = try connWith(fds[1], &.{
        .{ .name = "Authentication-Results", .value = "mail.relay.test; spf=pass smtp.mailfrom=ok.test" },
    });
    defer conn.deinit();

    const out = sealbuild.buildAarContent(&conn, our_id, &.{}).?;
    defer std.testing.allocator.free(out);

    try std.testing.expectEqualStrings("mail.relay.test; none", out);
}

test "a genuine result is carried through with the authserv-id stated once" {
    const fds = try posix.pipe2(.{ .NONBLOCK = true });
    defer posix.close(fds[0]);

    var conn = try connWith(fds[1], &.{
        .{ .name = "Authentication-Results", .value = "mail.relay.test; spf=pass smtp.mailfrom=ok.test" },
    });
    defer conn.deinit();

    const out = sealbuild.buildAarContent(&conn, our_id, &.{"spf"}).?;
    defer std.testing.allocator.free(out);

    // RFC 8617 §5.1.1: the AAR states the authserv-id once, then the results. The
    // per-header repeat is dropped by `resultsPart`.
    try std.testing.expectEqualStrings("mail.relay.test; spf=pass smtp.mailfrom=ok.test", out);
}

test "several genuine results are concatenated under one authserv-id" {
    const fds = try posix.pipe2(.{ .NONBLOCK = true });
    defer posix.close(fds[0]);

    // How the daemons actually stamp: one A-R per method, each written by a
    // different milter in the chain. Interleaved with a forgery claiming our id, to
    // check that rejecting one header does not disturb the others.
    var conn = try connWith(fds[1], &.{
        .{ .name = "Authentication-Results", .value = "mail.relay.test; spf=pass smtp.mailfrom=ok.test" },
        .{ .name = "Authentication-Results", .value = "mail.relay.test; dkim=pass header.d=evil.test" },
        .{ .name = "Authentication-Results", .value = "mail.relay.test; dmarc=fail (p=reject) header.from=ok.test" },
    });
    defer conn.deinit();

    const out = sealbuild.buildAarContent(&conn, our_id, &.{ "spf", "dmarc" }).?;
    defer std.testing.allocator.free(out);

    try std.testing.expectEqualStrings(
        "mail.relay.test; spf=pass smtp.mailfrom=ok.test; dmarc=fail (p=reject) header.from=ok.test",
        out,
    );
    try std.testing.expect(std.mem.indexOf(u8, out, "evil.test") == null);
}

test "an A-R claiming our authserv-id that asserts nothing parseable is rejected" {
    const fds = try posix.pipe2(.{ .NONBLOCK = true });
    defer posix.close(fds[0]);

    // This is what `assertsAnyMethod` uniquely protects, and it is not redundant
    // with the non-local-method check above. Both guards read the same
    // `ResultIterator`, which gives up at the first segment containing no `=`
    // (auth_results.zig:117) and therefore yields *nothing* for a value like this
    // one. A header asserting no results is outside no method set, so the
    // blacklist -- "reject if it claims a method we do not run" -- has nothing to
    // fire on. Only the whitelist -- "require a method we do run" -- stops it.
    //
    // Left unguarded, `resultsPart` would copy this text verbatim into the AAR and
    // this host would sign it. The immediate harm is bounded, since without an `=`
    // the attacker cannot spell `dkim=pass`, but it is arbitrary sender-controlled
    // prose inside a header we cryptographically vouch for and it violates the
    // RFC 8601 grammar the next hop parses. The general point is the one that
    // matters: a blacklist over what *our* parser recognises turns every parser
    // differential into a hole, and that early `return null` is one.
    //
    // Verified to have teeth: deleting the `assertsAnyMethod` guard fails this
    // test and nothing else in the suite.
    var conn = try connWith(fds[1], &.{
        .{ .name = "Authentication-Results", .value = "mail.relay.test; nothing here resembles a result" },
    });
    defer conn.deinit();

    const out = sealbuild.buildAarContent(&conn, our_id, &.{"spf"}).?;
    defer std.testing.allocator.free(out);

    try std.testing.expectEqualStrings("mail.relay.test; none", out);
}

// --- A-20: the ARC-Seal scope for a failed chain (RFC 8617 §5.1.2) -----------
//
// These exist because THE CONFORMANCE SUITE CANNOT SEE THIS DEFECT. Reverting the
// fix leaves the ValiMail signing suite at 17/17, measured: for a `cv=fail` chain a
// validator stops at the failed seal (§5.2 step 2) and never reaches ours, and `b=`
// is not byte-comparable because ValiMail's expected values come from dkimpy's
// alphabetical tag ordering. An external oracle covering 17 cases and an independent
// validator both miss it, so it is pinned directly.
//
// The rule inverts the usual one, which is why it is easy to get wrong: normally a
// seal covers the whole chain, but for a chain that does not validate §5.1.2 makes
// covering the prior sets a MUST NOT in effect -- there is no deterministic set of
// prior AS fields to sign, so the resulting signature is unverifiable rather than
// merely unusual.

const arc = @import("arc.zig");

/// Two prior sets, enough to tell "all of them" from "none of them".
fn priorSets() [2]arc.ArcSet {
    const empty = arc.ArcSet{
        .instance = 1,
        .aar_value = "i=1; example.org; none",
        .ams_value = "i=1; a=rsa-sha256; b=AAAA",
        .as_value = "i=1; cv=none; a=rsa-sha256; b=BBBB",
        .seal_cv = .none,
        .seal_algorithm = "rsa-sha256",
        .seal_domain = "example.org",
        .seal_selector = "s1",
        .seal_signature = "BBBB",
        .ams_algorithm = "rsa-sha256",
        .ams_domain = "example.org",
        .ams_selector = "s1",
        .ams_signature = "AAAA",
        .ams_body_hash = "CCCC",
        .ams_canonicalization = "relaxed/relaxed",
        .ams_signed_headers = "from",
    };
    var second = empty;
    second.instance = 2;
    second.seal_cv = .pass;
    return .{ empty, second };
}

test "a cv=fail seal covers only the new set, not the prior chain" {
    const sets = priorSets();
    // The MUST in §5.1.2: as if this newest ARC Set were the only set present.
    try std.testing.expectEqual(@as(usize, 0), sealbuild.sealScope(.fail, &sets).len);
}

test "a live chain's seal still covers every prior set" {
    const sets = priorSets();
    // The inverse must keep working: narrowing the scope for a passing chain would
    // break the chain of custody ARC exists to provide.
    try std.testing.expectEqual(@as(usize, 2), sealbuild.sealScope(.pass, &sets).len);
    try std.testing.expectEqual(@as(usize, 2), sealbuild.sealScope(.none, &sets).len);
    // `unknown` means no determination was made. It is not `fail`, so it must not
    // silently take the narrowed path.
    try std.testing.expectEqual(@as(usize, 2), sealbuild.sealScope(.unknown, &sets).len);
}

// --- A-19: a chain already marked cv=fail cannot be continued (§5.1.3) -------
//
// "Once broken, the chain cannot be continued, as the chain of custody is no longer
// valid, and responsibility for the message has been lost."
//
// The distinction these tests protect is the one that makes the rule subtle: a chain
// that fails validation HERE must be sealed cv=fail, because that is what records
// the break. Only a break an EARLIER hop already recorded stops us sealing. Getting
// that backwards would stop us marking newly detected failures, which is worse than
// the defect being fixed.

test "an existing cv=fail seal marks the chain as already broken" {
    var sets = priorSets();
    try std.testing.expect(!arc.chainAlreadyBroken(&sets));

    sets[1].seal_cv = .fail;
    try std.testing.expect(arc.chainAlreadyBroken(&sets));
}

test "a broken seal anywhere in the chain counts, not just the newest" {
    var sets = priorSets();
    // §5.1.3 is about the chain, not the last link: an earlier hop having recorded
    // the break is just as terminal, and a later cv=pass cannot revive it.
    sets[0].seal_cv = .fail;
    sets[1].seal_cv = .pass;
    try std.testing.expect(arc.chainAlreadyBroken(&sets));
}

test "an empty chain is not broken, it is absent" {
    // No sets means i=1 and cv=none, not a refusal to seal. Conflating "nothing to
    // continue" with "cannot continue" would stop this daemon sealing unsigned mail
    // at all, which is the common case.
    try std.testing.expect(!arc.chainAlreadyBroken(&.{}));
}
