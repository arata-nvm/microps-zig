const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{ .default_target = .{ .os_tag = .linux } });
    const optimize = b.standardOptimizeOption(.{});

    // build options

    const hexdump = b.option(bool, "hexdump", "Enable debugdump output") orelse false;

    const options = b.addOptions();
    options.addOption(bool, "hexdump", hexdump);

    const options_mod = options.createModule();

    // microps module

    const microps_mod = b.createModule(.{
        .root_source_file = b.path("src/microps.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true, // pthread, clock_gettime
    });

    microps_mod.addImport("build_options", options_mod);

    // sock module

    const sock_mod = b.createModule(.{
        .root_source_file = b.path("src/c/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true, // pthread, clock_gettime
        .imports = &.{
            .{ .name = "microps", .module = microps_mod },
        },
    });

    sock_mod.addImport("build_options", options_mod);
    sock_mod.addIncludePath(b.path("include"));

    const sock_lib = b.addLibrary(.{
        .linkage = .static,
        .name = "sock",
        .root_module = sock_mod,
    });

    // test application

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

    const run_test = b.addRunArtifact(test_exe);
    if (b.args) |args| {
        run_test.addArgs(args);
    }

    const run_step = b.step("run", "Run the test app");
    run_step.dependOn(&run_test.step);

    // example/test.c application

    const example_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    example_mod.addCSourceFile(.{ .file = b.path("example/test.c") });
    example_mod.addIncludePath(b.path("include"));
    example_mod.linkLibrary(sock_lib);

    const example_exe = b.addExecutable(.{
        .name = "example",
        .root_module = example_mod,
    });
    b.installArtifact(example_exe);

    const run_example = b.addRunArtifact(example_exe);
    if (b.args) |args| {
        run_example.addArgs(args);
    }

    const run_example_step = b.step("run-example", "Run the example app");
    run_example_step.dependOn(&run_example.step);

    // check step

    const check_step = b.step("check", "Check if test compiles");
    check_step.dependOn(&test_exe.step);
    check_step.dependOn(&sock_lib.step);

    // tap application

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

    const run_tap = b.addRunArtifact(tap_exe);
    if (b.args) |args| {
        run_tap.addArgs(args);
    }

    const run_tap_step = b.step("run-tap", "Run the tap app");
    run_tap_step.dependOn(&run_tap.step);

    // unit tests

    const unit_tests = b.addTest(.{
        .root_module = microps_mod,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);

    run_unit_tests.skip_foreign_checks = true;

    const unit_test_step = b.step("test", "Run unit tests");
    unit_test_step.dependOn(&run_unit_tests.step);

    // tap device setup

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
