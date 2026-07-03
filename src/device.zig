const std = @import("std");

const utils = @import("util.zig");
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

    pub fn init(typ: DeviceType, mtu: u16, hlen: u16, alen: u16) Self {
        return Self{
            .index = 0,
            .name_buf = [_]u8{0} ** IFNAMSIZ,
            .name_len = 0,
            .type = typ,
            .mtu = mtu,
            .flags = 0,
            .hlen = hlen,
            .alen = alen,
            .addr = undefined,
            .broadcast = undefined,
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
        utils.infof(@src(), "dev={s}", .{self.name()});
        if (self.is_up()) {
            utils.errorf(@src(), "already opened, dev={s}", .{self.name()});
            return error.DeviceAlreadyOpened;
        }
        self.flags |= @intFromEnum(DeviceFlag.UP);
    }

    pub fn close(self: *Self) !void {
        utils.infof(@src(), "dev={s}", .{self.name()});
        if (!self.is_up()) {
            utils.errorf(@src(), "not opened, dev={s}", .{self.name()});
            return error.DeviceNotOpened;
        }
        self.flags &= ~@intFromEnum(DeviceFlag.UP);
    }

    pub fn output(self: *Self, typ: u16, data: []const u8) !void {
        utils.debugf(@src(), "dev={s}, type={x:0>4}, len={d}", .{ self.name(), typ, data.len });
        utils.debugdump(data);
        if (!self.is_up()) {
            utils.errorf(@src(), "not opened: dev={s}", .{self.name()});
            return error.DeviceNotOpened;
        }
        if (self.mtu < data.len) {
            utils.errorf(@src(), "too long, dev={s}, mtu={d}, len={d}", .{ self.name(), self.mtu, data.len });
            return error.DeviceOutputTooLong;
        }
    }

    pub fn name(self: *Self) []const u8 {
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

    utils.infof(@src(), "success, dev={s}, index={d}", .{ ptr.name(), ptr.index });

    return ptr;
}

pub fn get_all() []const *Device {
    return devices.items;
}
