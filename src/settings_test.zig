//! Tests for `settings.zig`.
//!
//! In a separate file following the `dns/packet_test.zig` precedent, so the
//! configuration parser itself stays readable at a glance. Pulled into the test
//! build by `main.zig`.

const std = @import("std");

const securemilter = @import("securemilter");
const config_mod = securemilter.config;

const settings = @import("settings.zig");
const Mode = settings.Mode;
const OnDnsError = settings.OnDnsError;
const parseMode = settings.parseMode;
const parseOnDnsError = settings.parseOnDnsError;
const parseArcConfig = settings.parseArcConfig;

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
    defer std.testing.allocator.free(arc_cfg.modes);
    defer std.testing.allocator.free(arc_cfg.dns_nameservers);
    defer std.testing.allocator.free(arc_cfg.local_auth_methods);

    try std.testing.expectEqualStrings("mail.test.com", arc_cfg.authserv_id);
    try std.testing.expectEqual(@as(usize, 1), arc_cfg.listen_addresses.len);
    try std.testing.expectEqual(@as(usize, 1), arc_cfg.modes.len);
    try std.testing.expectEqual(Mode.verify_only, arc_cfg.modes[0]);
}

test "local auth methods default to none" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    const arc_cfg = try parseArcConfig(std.testing.allocator, &cfg);
    defer std.testing.allocator.free(arc_cfg.listen_addresses);
    defer std.testing.allocator.free(arc_cfg.modes);
    defer std.testing.allocator.free(arc_cfg.dns_nameservers);
    defer std.testing.allocator.free(arc_cfg.local_auth_methods);

    // A sealer that authenticates nothing locally must not vouch for anything.
    try std.testing.expectEqual(@as(usize, 0), arc_cfg.local_auth_methods.len);
    try std.testing.expect(!arc_cfg.strip_auth_results);
}

test "local auth methods parse as a comma separated list" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
        \\LocalAuthMethods = spf, dkim ,dmarc
        \\StripAuthResults = yes
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    const arc_cfg = try parseArcConfig(std.testing.allocator, &cfg);
    defer std.testing.allocator.free(arc_cfg.listen_addresses);
    defer std.testing.allocator.free(arc_cfg.modes);
    defer std.testing.allocator.free(arc_cfg.dns_nameservers);
    defer std.testing.allocator.free(arc_cfg.local_auth_methods);

    try std.testing.expectEqual(@as(usize, 3), arc_cfg.local_auth_methods.len);
    try std.testing.expectEqualStrings("spf", arc_cfg.local_auth_methods[0]);
    try std.testing.expectEqualStrings("dkim", arc_cfg.local_auth_methods[1]);
    try std.testing.expectEqualStrings("dmarc", arc_cfg.local_auth_methods[2]);
    try std.testing.expect(arc_cfg.strip_auth_results);
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
    defer std.testing.allocator.free(arc_cfg.modes);
    defer std.testing.allocator.free(arc_cfg.dns_nameservers);
    defer std.testing.allocator.free(arc_cfg.local_auth_methods);

    try std.testing.expectEqual(Mode.seal_only, arc_cfg.modes[0]);
    try std.testing.expectEqualStrings("test.com", arc_cfg.seal_domain.?);
    try std.testing.expectEqualStrings("arc2026", arc_cfg.seal_selector.?);
}

// A-2 regression. Before the fix, `mode` was one variable written by every
// listener section in turn, so this config ran BOTH sockets in seal mode and
// the verify listener silently sealed.
test "each listener keeps its own mode" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
        \\SealDomain = test.com
        \\SealSelector = arc2026
        \\
        \\[listener:verify]
        \\Socket = inet:8895@0.0.0.0
        \\Mode = verify
        \\
        \\[listener:seal]
        \\Socket = inet:8896@0.0.0.0
        \\Mode = seal
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    const arc_cfg = try parseArcConfig(std.testing.allocator, &cfg);
    defer std.testing.allocator.free(arc_cfg.listen_addresses);
    defer std.testing.allocator.free(arc_cfg.modes);
    defer std.testing.allocator.free(arc_cfg.dns_nameservers);
    defer std.testing.allocator.free(arc_cfg.local_auth_methods);

    try std.testing.expectEqual(@as(usize, 2), arc_cfg.listen_addresses.len);
    try std.testing.expectEqual(arc_cfg.listen_addresses.len, arc_cfg.modes.len);
    try std.testing.expectEqual(Mode.verify_only, arc_cfg.modes[0]);
    try std.testing.expectEqual(Mode.seal_only, arc_cfg.modes[1]);
}

// Declaration order in the file decides the index, because that is the order
// the worker binds them in and therefore the index it reports on a connection.
test "listener modes follow declaration order" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:a]
        \\Socket = inet:8896@0.0.0.0
        \\Mode = seal
        \\
        \\[listener:b]
        \\Socket = inet:8895@0.0.0.0
        \\Mode = verify
        \\
        \\[listener:c]
        \\Socket = inet:8897@0.0.0.0
        \\Mode = both
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    const arc_cfg = try parseArcConfig(std.testing.allocator, &cfg);
    defer std.testing.allocator.free(arc_cfg.listen_addresses);
    defer std.testing.allocator.free(arc_cfg.modes);
    defer std.testing.allocator.free(arc_cfg.dns_nameservers);
    defer std.testing.allocator.free(arc_cfg.local_auth_methods);

    try std.testing.expectEqual(@as(usize, 3), arc_cfg.modes.len);
    try std.testing.expectEqual(Mode.seal_only, arc_cfg.modes[0]);
    try std.testing.expectEqual(Mode.verify_only, arc_cfg.modes[1]);
    try std.testing.expectEqual(Mode.both, arc_cfg.modes[2]);
}

test "a listener without Mode inherits the global default" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
        \\Mode = both
        \\
        \\[listener:inherits]
        \\Socket = inet:8895@0.0.0.0
        \\
        \\[listener:overrides]
        \\Socket = inet:8896@0.0.0.0
        \\Mode = verify
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    const arc_cfg = try parseArcConfig(std.testing.allocator, &cfg);
    defer std.testing.allocator.free(arc_cfg.listen_addresses);
    defer std.testing.allocator.free(arc_cfg.modes);
    defer std.testing.allocator.free(arc_cfg.dns_nameservers);
    defer std.testing.allocator.free(arc_cfg.local_auth_methods);

    try std.testing.expectEqual(Mode.both, arc_cfg.modes[0]);
    try std.testing.expectEqual(Mode.verify_only, arc_cfg.modes[1]);
}

// The implicit default listener must still get a mode, or `modes` and
// `listen_addresses` fall out of step and every index lookup is wrong.
test "implicit default listener gets a mode" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    const arc_cfg = try parseArcConfig(std.testing.allocator, &cfg);
    defer std.testing.allocator.free(arc_cfg.listen_addresses);
    defer std.testing.allocator.free(arc_cfg.modes);
    defer std.testing.allocator.free(arc_cfg.dns_nameservers);
    defer std.testing.allocator.free(arc_cfg.local_auth_methods);

    try std.testing.expectEqual(@as(usize, 1), arc_cfg.listen_addresses.len);
    try std.testing.expectEqual(@as(usize, 1), arc_cfg.modes.len);
    try std.testing.expectEqual(Mode.verify_only, arc_cfg.modes[0]);
}

// --- A-12: On-DNSError ------------------------------------------------------

test "On-DNSError accepts the three policies and refuses anything else" {
    try std.testing.expectEqual(OnDnsError.tempfail, try parseOnDnsError("tempfail"));
    try std.testing.expectEqual(OnDnsError.skip_seal, try parseOnDnsError("skip-seal"));
    try std.testing.expectEqual(OnDnsError.seal_fail, try parseOnDnsError("seal-fail"));

    // Underscores are the enum tag spelling, not the config spelling; accepting
    // them would give two ways to write one value.
    try std.testing.expectError(error.InvalidOnDnsError, parseOnDnsError("skip_seal"));
    try std.testing.expectError(error.InvalidOnDnsError, parseOnDnsError("Tempfail"));
    try std.testing.expectError(error.InvalidOnDnsError, parseOnDnsError("defer"));
    try std.testing.expectError(error.InvalidOnDnsError, parseOnDnsError(""));
}

// The default is the one that cannot permanently damage a third party's chain,
// even though it is not the cheapest for this host.
test "On-DNSError defaults to tempfail and is read from the config" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    const arc_cfg = try parseArcConfig(std.testing.allocator, &cfg);
    defer std.testing.allocator.free(arc_cfg.listen_addresses);
    defer std.testing.allocator.free(arc_cfg.modes);
    defer std.testing.allocator.free(arc_cfg.dns_nameservers);
    defer std.testing.allocator.free(arc_cfg.local_auth_methods);

    try std.testing.expectEqual(OnDnsError.tempfail, arc_cfg.on_dns_error);

    const explicit_text =
        \\[global]
        \\AuthservID = mail.test.com
        \\On-DNSError = skip-seal
    ;

    var cfg2 = try config_mod.parse(std.testing.allocator, explicit_text);
    defer cfg2.deinit();

    const cfg2_parsed = try parseArcConfig(std.testing.allocator, &cfg2);
    defer std.testing.allocator.free(cfg2_parsed.listen_addresses);
    defer std.testing.allocator.free(cfg2_parsed.modes);
    defer std.testing.allocator.free(cfg2_parsed.dns_nameservers);
    defer std.testing.allocator.free(cfg2_parsed.local_auth_methods);

    try std.testing.expectEqual(OnDnsError.skip_seal, cfg2_parsed.on_dns_error);
}

// Found by an end-to-end lab test whose own `printf >> config` appended the
// setting after the last section header, so it landed in [listener:seal] and was
// ignored — the daemon used the default and said nothing. Refusing is the same
// answer A-2 got.
test "On-DNSError in a listener section is refused rather than ignored" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:seal]
        \\Socket = inet:8895@0.0.0.0
        \\Mode = seal
        \\On-DNSError = seal-fail
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    try std.testing.expectError(
        error.OnDnsErrorNotPerListener,
        parseArcConfig(std.testing.allocator, &cfg),
    );
}

test "a bad On-DNSError value stops the daemon rather than picking a policy" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
        \\On-DNSError = ignore
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    try std.testing.expectError(error.InvalidOnDnsError, parseArcConfig(std.testing.allocator, &cfg));
}

test "an unrecognised Mode is refused" {
    try std.testing.expectEqual(Mode.verify_only, try parseMode("verify"));
    try std.testing.expectEqual(Mode.seal_only, try parseMode("seal"));
    try std.testing.expectEqual(Mode.both, try parseMode("both"));

    try std.testing.expectError(error.InvalidMode, parseMode("sealing"));
    try std.testing.expectError(error.InvalidMode, parseMode("Verify"));
    try std.testing.expectError(error.InvalidMode, parseMode(""));

    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:typo]
        \\Socket = inet:8895@0.0.0.0
        \\Mode = sealing
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    try std.testing.expectError(error.InvalidMode, parseArcConfig(std.testing.allocator, &cfg));
}

// --- Reloadable: the snapshot SIGHUP publishes (audit A-14) -------------------
//
// This is fresh memory-management code on the reload path, and X-10 was a
// borrow-versus-own mistake that shipped because nothing tested the contract. The
// two properties worth pinning are that the snapshot is genuinely independent of the
// config it was built from, and that a failure partway through building one leaks
// nothing.

/// An `ArcConfig` whose strings live in `buf`, so a test can scribble over the
/// originals afterwards and see whether the snapshot noticed.
fn scratchConfig(authserv: []u8, headers: []u8, domain: []u8, methods: [][]const u8, ns: [][]const u8) settings.ArcConfig {
    return .{
        .authserv_id = authserv,
        .listen_addresses = &.{},
        .worker_threads = 1,
        .pid_file = "/nonexistent",
        .foreground = true,
        .user = null,
        .dns_nameservers = ns,
        .dns_timeout_ms = 1234,
        .dns_retries = 3,
        .dns_cache_size = 77,
        .dns_negative_ttl = 88,
        .modes = &.{},
        .seal_domain = domain,
        .seal_selector = "sel",
        .seal_key_file = null,
        .signed_headers = headers,
        .local_auth_methods = methods,
        .strip_auth_results = true,
        .zmq_endpoint = null,
        .zmq_topic = "arc",
        .limits = .{},
        .min_key_bits = .{ .bits = 2048, .raised = false },
        .on_dns_error = .skip_seal,
    };
}

test "a reloaded snapshot does not borrow from the config it came from" {
    // The property that makes reload safe rather than a use-after-free:
    // `reloadConfig` frees the parsed `Config` before it returns, so anything the
    // snapshot still points at is gone by the time the next message reads it. Tested
    // by overwriting the source buffers rather than by freeing them, so the result is
    // a deterministic comparison instead of a hope that the allocator notices.
    const a = std.testing.allocator;

    const authserv = try a.dupe(u8, "mail.first.test");
    defer a.free(authserv);
    const headers = try a.dupe(u8, "from:to:subject");
    defer a.free(headers);
    const domain = try a.dupe(u8, "first.example");
    defer a.free(domain);

    const method = try a.dupe(u8, "spf");
    defer a.free(method);
    const methods = try a.alloc([]const u8, 1);
    defer a.free(methods);
    methods[0] = method;

    const server = try a.dupe(u8, "10.0.0.1");
    defer a.free(server);
    const ns = try a.alloc([]const u8, 1);
    defer a.free(ns);
    ns[0] = server;

    var snap = try settings.Reloadable.init(a, scratchConfig(authserv, headers, domain, methods, ns));
    defer snap.deinit(a);

    // Scribble over every source string, including the list contents.
    @memset(authserv, 'X');
    @memset(headers, 'X');
    @memset(domain, 'X');
    @memset(method, 'X');
    @memset(server, 'X');

    try std.testing.expectEqualStrings("mail.first.test", snap.authserv_id);
    try std.testing.expectEqualStrings("from:to:subject", snap.signed_headers);
    try std.testing.expectEqualStrings("first.example", snap.seal_domain.?);
    try std.testing.expectEqual(@as(usize, 1), snap.local_auth_methods.len);
    try std.testing.expectEqualStrings("spf", snap.local_auth_methods[0]);
    try std.testing.expectEqual(@as(usize, 1), snap.dns_config.nameservers.len);
    try std.testing.expectEqualStrings("10.0.0.1", snap.dns_config.nameservers[0]);

    // Scalars come across too, including the two an operator would change during an
    // incident and that A-14 made silently ineffective.
    try std.testing.expectEqual(@as(u32, 2048), snap.min_key_bits);
    try std.testing.expectEqual(OnDnsError.skip_seal, snap.on_dns_error);
    try std.testing.expect(snap.strip_all);
    try std.testing.expectEqual(@as(u32, 1234), snap.dns_config.timeout_ms);
    try std.testing.expectEqual(@as(u32, 88), snap.dns_config.negative_ttl);
}

test "a snapshot that fails partway through frees what it had already copied" {
    // Six separate allocations plus the per-element dupes inside two lists, each
    // guarded by its own errdefer. Stated as a property over every allocation the
    // function performs rather than against a hand-picked index, so it cannot rot as
    // the field list changes -- the same shape as the X-8 test over `emitArcSet`.
    //
    // `FailingAllocator` reports any block still outstanding when the test ends, so a
    // missing errdefer fails here rather than becoming a leak on every SIGHUP that
    // happens to land under memory pressure.
    var saw_success = false;
    var saw_failure = false;

    var fail_index: usize = 0;
    while (fail_index < 12) : (fail_index += 1) {
        const a = std.testing.allocator;

        const authserv = try a.dupe(u8, "mail.first.test");
        defer a.free(authserv);
        const headers = try a.dupe(u8, "from:to");
        defer a.free(headers);
        const domain = try a.dupe(u8, "first.example");
        defer a.free(domain);
        const methods = try a.alloc([]const u8, 2);
        defer a.free(methods);
        methods[0] = "spf";
        methods[1] = "dkim";
        const ns = try a.alloc([]const u8, 2);
        defer a.free(ns);
        ns[0] = "10.0.0.1";
        ns[1] = "10.0.0.2";

        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = fail_index });
        const cfg = scratchConfig(authserv, headers, domain, methods, ns);

        if (settings.Reloadable.init(failing.allocator(), cfg)) |made| {
            saw_success = true;
            var snap = made;
            snap.deinit(failing.allocator());
        } else |_| {
            saw_failure = true;
        }

        // Nothing outstanding on either path.
        try std.testing.expectEqual(failing.allocations, failing.deallocations);
    }

    // Guard against the loop passing because it exercised nothing.
    try std.testing.expect(saw_failure);
    try std.testing.expect(saw_success);
}

test "the strip policy always claims arc, and carries strip_all through" {
    // `own_methods` names what this daemon asserts, so it is a property of the
    // program. `strip_all` is the operator's, and it is reloadable.
    const a = std.testing.allocator;
    const authserv = try a.dupe(u8, "mail.first.test");
    defer a.free(authserv);
    const headers = try a.dupe(u8, "from");
    defer a.free(headers);
    const domain = try a.dupe(u8, "first.example");
    defer a.free(domain);
    const methods = try a.alloc([]const u8, 0);
    defer a.free(methods);
    const ns = try a.alloc([]const u8, 0);
    defer a.free(ns);

    var cfg = scratchConfig(authserv, headers, domain, methods, ns);
    cfg.strip_auth_results = false;

    var snap = try settings.Reloadable.init(a, cfg);
    defer snap.deinit(a);

    const policy = snap.stripPolicy();
    try std.testing.expectEqual(@as(usize, 1), policy.own_methods.len);
    try std.testing.expectEqualStrings("arc", policy.own_methods[0]);
    try std.testing.expect(!policy.strip_all);
}
