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

    const exe = b.addExecutable(.{
        .name = "test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/test/test.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "microps", .module = microps_mod },
            },
        }),
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run the test app");
    run_step.dependOn(&run_cmd.step);

    const unit_tests = b.addTest(.{ .root_module = microps_mod });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    run_unit_tests.skip_foreign_checks = true;
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
