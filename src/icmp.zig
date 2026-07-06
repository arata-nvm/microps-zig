const ip = @import("ip.zig");
const util = @import("util.zig");

pub fn init() !void {
    ip.registerProtocol(.icmp, input) catch |err| {
        util.errorf(@src(), "ip.registerProtocol() failure: err={t}", .{err});
        return error.IpRegisterProtocolFailure;
    };
}

fn input(hdr: *const ip.IpHdr, data: []const u8, iface: *ip.IpIface) !void {
    _ = iface;
    util.debugf(@src(), "{f} => {f}, len={d}", .{ hdr.src, hdr.dst, data.len });
    util.debugdump(data);
}
