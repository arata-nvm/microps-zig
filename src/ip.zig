const device = @import("device.zig");
const net = @import("net.zig");
const util = @import("util.zig");

pub fn init() !void {
    net.register(net.ProtocolType.IP, input) catch |err| {
        util.errorf(@src(), "net.register() failure: {t}", .{err});
        return err;
    };
}

fn input(data: []const u8, dev: *device.Device) !void {
    util.debugf(@src(), "dev={s}, len={d}", .{ dev.name(), data.len });
    util.debugdump(data);
}
