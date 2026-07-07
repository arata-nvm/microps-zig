const std = @import("std");

const device = @import("../device.zig");
const net = @import("../net.zig");
const util = @import("../util.zig");

const mtu = std.math.maxInt(u16);

pub fn init() !*device.Device {
    const dev = device.Device.init(.loopback, mtu, .{ .loopback = true }, 0, 0, ops);
    const ptr = device.register(dev) catch |err| {
        util.errorf(@src(), "device.register() failure: {t}", .{err});
        return err;
    };
    util.infof(@src(), "success, dev={s}\n", .{ptr.name()});
    return ptr;
}

const ops = device.DeviceOps{
    .openFn = null,
    .closeFn = null,
    .outputFn = output,
};

fn output(dev: *device.Device, typ: net.ProtocolType, data: []const u8) !void {
    util.debugf(@src(), "dev={s}, type={d:0>4}, len={d}", .{ dev.name(), typ, data.len });
    util.debugdump(data);
    try net.input(typ, data, dev);
}
