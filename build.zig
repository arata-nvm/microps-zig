const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{
        .default_target = .{ .os_tag = .linux },
    });
    const optimize = b.standardOptimizeOption(.{});

    const hexdump = b.option(bool, "hexdump", "Enable debugdump output") orelse false;
    const options = b.addOptions();
    options.addOption(bool, "hexdump", hexdump);

    const microps_mod = b.createModule(.{
        .root_source_file = b.path("src/microps.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true, // pthread, clock_gettime
    });
    microps_mod.addImport("build_options", options.createModule());

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/test/test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "microps", .module = microps_mod },
        },
    });

    const test_exe = b.addExecutable(.{
        .name = "test",
        .root_module = test_mod,
    });
    b.installArtifact(test_exe);

    const run_cmd = b.addRunArtifact(test_exe);
    run_cmd.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run the test app");
    run_step.dependOn(&run_cmd.step);

    const test_exe_check = b.addExecutable(.{
        .name = "test",
        .root_module = test_mod,
    });

    const check = b.step("check", "Check if test compiles");
    check.dependOn(&test_exe_check.step);

    const tap_mod = b.createModule(.{
        .root_source_file = b.path("src/test/tap.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "microps", .module = microps_mod },
        },
    });

    const tap_exe = b.addExecutable(.{
        .name = "tap",
        .root_module = tap_mod,
    });
    b.installArtifact(tap_exe);

    const run_tap_cmd = b.addRunArtifact(tap_exe);
    run_tap_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_tap_cmd.addArgs(args);
    const run_tap_step = b.step("run-tap", "Run the tap app");
    run_tap_step.dependOn(&run_tap_cmd.step);

    const unit_tests = b.addTest(.{ .root_module = microps_mod });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    run_unit_tests.skip_foreign_checks = true;
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    const tap_cmd = b.addSystemCommand(&.{
        "sh", "-c",
        \\ [ "$(uname)" = Linux ] || { echo "tap is only supported on Linux"; exit 1; }
        \\ ip addr show tap0 2>/dev/null || (
        \\   echo "Create 'tap0'"
        \\   sudo ip tuntap add mode tap user $USER name tap0
        \\   sudo sysctl -w net.ipv6.conf.tap0.disable_ipv6=1
        \\   sudo ip addr add 192.0.2.1/24 dev tap0
        \\   sudo ip link set tap0 up
        \\   ip addr show tap0
        \\ )
    });
    tap_cmd.has_side_effects = true;
    const tap_step = b.step("tap", "Create and configure tap0 device");
    tap_step.dependOn(&tap_cmd.step);
}
