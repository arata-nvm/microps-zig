const std = @import("std");

const device = @import("../device.zig");
const net = @import("../net.zig");
const platform = @import("../platform.zig");
const util = @import("../util.zig");

const mtu = std.math.maxInt(u16);

pub fn init() !*device.Device {
    const allocator = platform.allocator();
    const dev = try allocator.create(device.Device);
    dev.* = device.Device.init(.loopback, mtu, .{ .loopback = true }, 0, 0, ops);
    device.register(dev) catch |err| {
        util.errorf(@src(), "device.register() failure: {t}", .{err});
        return err;
    };
    util.infof(@src(), "success, dev={s}\n", .{dev.name()});
    return dev;
}

const ops = device.DeviceOps{
    .openFn = null,
    .closeFn = null,
    .outputFn = output,
};

fn output(dev: *device.Device, typ: net.ProtocolType, data: []const u8, _: ?[]const u8) !void {
    util.debugf(@src(), "dev={s}, type=0x{x:0>4}, len={d}", .{ dev.name(), typ, data.len });
    util.debugdump(data);
    try net.input(typ, data, dev);
}
