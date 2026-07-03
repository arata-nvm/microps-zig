const std = @import("std");

const util = @import("util.zig");
const net = @import("net.zig");
const platform = @import("platform/linux/platform.zig");

pub const DeviceType = enum(u16) {
    DUMMY = 0,
    ETHERNET = 1,
    LOOPBACK = 2,
};

pub const DeviceFlag = enum(u16) {
    UP = 0x0001,
    LOOPBACK = 0x0010,
    BROADCAST = 0x0020,
    P2P = 0x0040,
    NEED_ARP = 0x0100,
};

pub const DeviceFlags = u16;

pub const DeviceOps = struct {
    openFn: ?*const fn (*Device) anyerror!void = null,
    closeFn: ?*const fn (*Device) anyerror!void = null,
    outputFn: *const fn (*Device, net.ProtocolType, []const u8) anyerror!void,

    pub fn open(self: DeviceOps, dev: *Device) !void {
        const f = self.openFn orelse return;
        return f(dev);
    }

    pub fn close(self: DeviceOps, dev: *Device) !void {
        const f = self.closeFn orelse return;
        return f(dev);
    }

    pub fn output(self: DeviceOps, dev: *Device, typ: net.ProtocolType, data: []const u8) !void {
        return self.outputFn(dev, typ, data);
    }
};

const IFNAMSIZ = 16;
const ADDR_LEN = 6;

pub const Device = struct {
    pub const Self = @This();

    index: usize,
    name_buf: [IFNAMSIZ]u8,
    name_len: usize,
    type: DeviceType,
    mtu: u16,
    flags: DeviceFlags,
    hlen: u16,
    alen: u16,
    addr: [ADDR_LEN]u8,
    broadcast: [ADDR_LEN]u8,

    ops: DeviceOps,

    pub fn init(typ: DeviceType, mtu: u16, flags: DeviceFlags, hlen: u16, alen: u16, ops: DeviceOps) Self {
        return Self{
            .index = 0,
            .name_buf = [_]u8{0} ** IFNAMSIZ,
            .name_len = 0,
            .type = typ,
            .mtu = mtu,
            .flags = flags,
            .hlen = hlen,
            .alen = alen,
            .addr = undefined,
            .broadcast = undefined,
            .ops = ops,
        };
    }

    fn initRegistered(dev: Device, index: usize) !Device {
        var result = dev;
        result.index = index;
        const name_buf = try std.fmt.bufPrint(&result.name_buf, "net{d}", .{index});
        result.name_len = name_buf.len;
        return result;
    }

    pub fn open(self: *Self) !void {
        util.infof(@src(), "dev={s}", .{self.name()});
        if (self.is_up()) {
            util.errorf(@src(), "already opened, dev={s}", .{self.name()});
            return error.DeviceAlreadyOpened;
        }
        self.ops.open(self) catch |err| {
            util.errorf(@src(), "ops.open() failure, dev={s}, err={t}", .{ self.name(), err });
            return err;
        };
        self.flags |= @intFromEnum(DeviceFlag.UP);
    }

    pub fn close(self: *Self) !void {
        util.infof(@src(), "dev={s}", .{self.name()});
        if (!self.is_up()) {
            util.errorf(@src(), "not opened, dev={s}", .{self.name()});
            return error.DeviceNotOpened;
        }
        self.ops.close(self) catch |err| {
            util.errorf(@src(), "ops.close() failure, dev={s}, err={t}", .{ self.name(), err });
            return err;
        };
        self.flags &= ~@intFromEnum(DeviceFlag.UP);
    }

    pub fn output(self: *Self, typ: net.ProtocolType, data: []const u8) !void {
        util.debugf(@src(), "dev={s}, type={x:0>4}, len={d}", .{ self.name(), typ, data.len });
        util.debugdump(data);
        if (!self.is_up()) {
            util.errorf(@src(), "not opened: dev={s}", .{self.name()});
            return error.DeviceNotOpened;
        }
        if (self.mtu < data.len) {
            util.errorf(@src(), "too long, dev={s}, mtu={d}, len={d}", .{ self.name(), self.mtu, data.len });
            return error.DeviceOutputTooLong;
        }
        self.ops.output(self, typ, data) catch |err| {
            util.errorf(@src(), "ops.output() failure, dev={s}, err={t}", .{ self.name(), err });
            return err;
        };
    }

    pub fn name(self: *const Self) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    pub fn is_up(self: *Self) bool {
        return (self.flags & @intFromEnum(DeviceFlag.UP)) != 0;
    }

    pub fn state(self: *Self) []const u8 {
        if (self.is_up()) {
            return "UP";
        } else {
            return "DOWN";
        }
    }
};

var devices: std.ArrayList(*Device) = .empty;
var device_index: usize = 0;

pub fn register(dev: Device) !*Device {
    const allocator = platform.allocator;

    const ptr = try allocator.create(Device);
    errdefer allocator.destroy(ptr);

    ptr.* = try Device.initRegistered(dev, device_index);

    try devices.append(platform.allocator, ptr);
    device_index += 1;

    util.infof(@src(), "success, dev={s}, index={d}", .{ ptr.name(), ptr.index });

    return ptr;
}

pub fn get_all() []const *Device {
    return devices.items;
}
