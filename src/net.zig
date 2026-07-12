const std = @import("std");

const arp = @import("arp.zig");
const platform = @import("platform.zig");
const device = @import("device.zig");
const icmp = @import("icmp.zig");
const ip = @import("ip.zig");
const udp = @import("udp.zig");
const util = @import("util.zig");

const intr = platform.intr;

// TODO: etherの具体的な実装に依存してしまっているので、分離できると好ましい
pub const ProtocolType = @import("ether.zig").EtherType;

pub const ProtocolHandler = *const fn (data: []const u8, dev: *device.Device) anyerror!void;

pub const Protocol = struct {
    const Self = @This();

    const ProtocolQueueEntry = struct {
        data: []const u8,
        dev: *device.Device,
    };

    type: ProtocolType,
    handler: ProtocolHandler,
    lock: platform.Lock,
    queue: util.Queue(ProtocolQueueEntry),

    pub fn queuePush(self: *Self, data: []const u8, dev: *device.Device) !void {
        self.lock.acquire();
        defer self.lock.release();

        const allocator = platform.allocator();
        const copied = try allocator.dupe(u8, data);
        errdefer allocator.free(copied);

        try self.queue.push(.{
            .dev = dev,
            .data = copied,
        });

        util.debugf(@src(), "success, proto=0x{x:0>4}, queue.num={d}", .{ self.type, self.queue.num });
    }

    pub fn queuePop(self: *Self) ?ProtocolQueueEntry {
        self.lock.acquire();
        defer self.lock.release();

        const entry = self.queue.pop() orelse return null;
        util.debugf(@src(), "success, proto=0x{x:0>4}, queue.num={d}", .{ self.type, self.queue.num });
        return entry;
    }
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
        .lock = .{},
        .queue = .{},
    });

    util.infof(@src(), "success, type={t}", .{typ});
}

pub fn input(typ: ProtocolType, data: []const u8, dev: *device.Device) !void {
    util.debugf(@src(), "dev={s}, type=0x{x:0>4}, len={d}", .{ dev.name(), typ, data.len });
    util.debugdump(data);
    for (protocols.items) |*proto| {
        if (proto.type == typ) {
            proto.queuePush(data, dev) catch |err| {
                util.errorf(@src(), "proto.push_queue() failure: {t}", .{err});
                return err;
            };
            intr.raise(intr.irq_soft) catch |err| {
                util.errorf(@src(), "intr.raise() failure: {t}", .{err});
                return err;
            };
            return;
        }
    }
    // allow unsupported protocols
}

pub fn sortirq_handler(_: u32, _: *void) !void {
    const allocator = platform.allocator();
    for (protocols.items) |*proto| {
        while (proto.queuePop()) |entry| {
            defer allocator.free(entry.data);
            try proto.handler(entry.data, entry.dev);
        }
    }
}

pub fn init(options: platform.InitOptions) !void {
    util.infof(@src(), "initialize...", .{});
    platform.init(options) catch |err| {
        util.errorf(@src(), "platform.init() failure: {t}", .{err});
        return err;
    };

    arp.init() catch |err| {
        util.errorf(@src(), "arp.init() failure: {t}", .{err});
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
    udp.init() catch |err| {
        util.errorf(@src(), "udp.init() failure: {t}", .{err});
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
