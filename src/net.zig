const std = @import("std");

const platform = @import("platform/linux/platform.zig");
const util = @import("util.zig");

pub fn init() !void {
    util.infof(@src(), "initialize...", .{});
    platform.init() catch |err| {
        util.errorf(@src(), "platform.init() failure: {t}", .{err});
        return err;
    };
    util.infof(@src(), "success", .{});
}

pub fn run() !void {
    util.infof(@src(), "startup...", .{});
    platform.run() catch |err| {
        util.errorf(@src(), "platform.run() failure: {t}", .{err});
        return err;
    };
    util.infof(@src(), "success", .{});
}

pub fn shutdown() !void {
    util.infof(@src(), "shutting down...", .{});
    platform.shutdown() catch |err| {
        util.errorf(@src(), "platform.shutdown() failure: {t}", .{err});
        return err;
    };
    util.infof(@src(), "success", .{});
}
