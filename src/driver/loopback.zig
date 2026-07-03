const std = @import("std");

const device = @import("../device.zig");
const util = @import("../util.zig");

pub const MTU = std.math.maxInt(u16);

pub fn init() !*device.Device {
    const dev = device.Device.init(device.DeviceType.LOOPBACK, MTU, @intFromEnum(device.DeviceFlag.LOOPBACK), 0, 0, ops);
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

fn output(dev: *device.Device, typ: u16, data: []const u8) !void {
    util.debugf(@src(), "dev={s}, type={d:0>4}, len={d}", .{ dev.name(), typ, data.len });
    util.debugdump(data);
    return dev.input(typ, data);
}
