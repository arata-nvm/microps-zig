const std = @import("std");

const arp = @import("arp.zig");
const platform = @import("platform.zig");
const device = @import("device.zig");
const icmp = @import("icmp.zig");
const ip = @import("ip.zig");
const util = @import("util.zig");

// TODO: etherの具体的な実装に依存してしまっているので、分離できると好ましい
pub const ProtocolType = @import("ether.zig").EtherType;

pub const ProtocolHandler = *const fn (data: []const u8, dev: *device.Device) anyerror!void;

pub const Protocol = struct {
    type: ProtocolType,
    handler: ProtocolHandler,
};

var protocols: std.ArrayList(Protocol) = .empty;

pub fn register(typ: ProtocolType, handler: ProtocolHandler) !void {
    for (protocols.items) |proto| {
        if (proto.type == typ) {
            util.errorf(@src(), "already registered, type={t}", .{typ});
            return error.ProtocolAlreadyRegistered;
        }
    }

    const allocator = platform.allocator();
    try protocols.append(allocator, .{
        .type = typ,
        .handler = handler,
    });

    util.infof(@src(), "success, type={t}", .{typ});
}

pub fn input(typ: ProtocolType, data: []const u8, dev: *device.Device) !void {
    util.debugf(@src(), "dev={s}, type=0x{x:0>4}, len={d}", .{ dev.name(), typ, data.len });
    util.debugdump(data);
    for (protocols.items) |proto| {
        if (proto.type == typ) {
            try proto.handler(data, dev);
            return;
        }
    }
    // allow unsupported protocols
}

pub fn init(options: platform.InitOptions) !void {
    util.infof(@src(), "initialize...", .{});
    platform.init(options) catch |err| {
        util.errorf(@src(), "platform.init() failure: {t}", .{err});
        return err;
    };
    ip.init() catch |err| {
        util.errorf(@src(), "ip.init() failure: {t}", .{err});
        return err;
    };
    icmp.init() catch |err| {
        util.errorf(@src(), "icmp.init() failure: {t}", .{err});
        return err;
    };
    arp.init() catch |err| {
        util.errorf(@src(), "arp.init() failure: {t}", .{err});
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
    for (device.getAll()) |dev| {
        try dev.open();
    }
    util.infof(@src(), "success", .{});
}

pub fn shutdown() !void {
    util.infof(@src(), "shutting down...", .{});
    platform.shutdown() catch |err| {
        util.errorf(@src(), "platform.shutdown() failure: {t}", .{err});
        return err;
    };
    for (device.getAll()) |dev| {
        try dev.close();
    }
    util.infof(@src(), "success", .{});
}
