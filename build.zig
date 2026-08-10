const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const securemilter_dep = b.dependency("securemilter", .{
        .target = target,
        .optimize = optimize,
    });
    const securemilter_mod = securemilter_dep.module("securemilter");

    const crypto_dep = b.dependency("securemilter_crypto", .{
        .target = target,
        .optimize = optimize,
    });
    const crypto_mod = crypto_dep.module("securemilter_crypto");

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "securemilter", .module = securemilter_mod },
            .{ .name = "securemilter_crypto", .module = crypto_mod },
        },
    });

    const exe = b.addExecutable(.{
        .name = "securearc",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    // securearc-testkey CLI tool (needs securemilter for DNS + securemilter_crypto for key loading)
    const testkey_mod = b.createModule(.{
        .root_source_file = b.path("src/testkey.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "securemilter", .module = securemilter_mod },
            .{ .name = "securemilter_crypto", .module = crypto_mod },
        },
    });
    const testkey_exe = b.addExecutable(.{
        .name = "securearc-testkey",
        .root_module = testkey_mod,
    });
    b.installArtifact(testkey_exe);

    // securearc-check: validate one message's ARC chain and print the result.
    // Exists so the ValiMail arc_test_suite can drive the shipped verifier
    // directly, the way securespf-check lets the RFC 7208 suite drive SPF.
    const check_mod = b.createModule(.{
        .root_source_file = b.path("src/check.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "securemilter", .module = securemilter_mod },
            .{ .name = "securemilter_crypto", .module = crypto_mod },
        },
    });
    const check_exe = b.addExecutable(.{
        .name = "securearc-check",
        .root_module = check_mod,
    });
    b.installArtifact(check_exe);

    // securearc-seal exercises the daemon's sealing path against external
    // verifiers, not only the implementation's own validation.
    const seal_cli_mod = b.createModule(.{
        .root_source_file = b.path("src/seal_cli.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "securemilter", .module = securemilter_mod },
            .{ .name = "securemilter_crypto", .module = crypto_mod },
        },
    });
    const seal_cli_exe = b.addExecutable(.{
        .name = "securearc-seal",
        .root_module = seal_cli_mod,
    });
    b.installArtifact(seal_cli_exe);

    const test_step = b.step("test", "Run unit tests");

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "securemilter", .module = securemilter_mod },
            .{ .name = "securemilter_crypto", .module = crypto_mod },
        },
    });

    const main_tests = b.addTest(.{
        .root_module = test_mod,
    });

    const run_tests = b.addRunArtifact(main_tests);
    test_step.dependOn(&run_tests.step);

    // CLI roots are test targets because main.zig does not import them.
    const check_tests = b.addTest(.{ .root_module = check_mod });
    const run_check_tests = b.addRunArtifact(check_tests);
    test_step.dependOn(&run_check_tests.step);

    const seal_cli_tests = b.addTest(.{ .root_module = seal_cli_mod });
    const run_seal_cli_tests = b.addRunArtifact(seal_cli_tests);
    test_step.dependOn(&run_seal_cli_tests.step);

    // One canonical checker, shared from securemilter-lib rather than copied.
    const lint = b.addSystemCommand(&.{"sh"});
    lint.addFileArg(securemilter_dep.path("tools/check-line-limit.sh"));
    lint.addArg("src");
    lint.addArg(".line-limit-allow");
    if (b.args) |args| lint.addArgs(args);
    lint.has_side_effects = true;
    const lint_step = b.step("lint", "Fail on source files over the 400-line limit");
    lint_step.dependOn(&lint.step);
}
