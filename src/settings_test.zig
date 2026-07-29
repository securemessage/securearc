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
