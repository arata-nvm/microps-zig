const std = @import("std");

const util = @import("util.zig");

pub const EtherAddr = struct {
    const Self = @This();

    const ADDR_LEN = 6;

    addr: [ADDR_LEN]u8,

    pub const any = Self{ .addr = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };
    pub const broadcast = Self{ .addr = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };

    pub fn fromBytes(bytes: [ADDR_LEN]u8) Self {
        return Self{ .addr = bytes };
    }

    pub fn format(
        self: @This(),
        writer: *std.Io.Writer,
    ) !void {
        try writer.print("{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
            self.addr[0],
            self.addr[1],
            self.addr[2],
            self.addr[3],
            self.addr[4],
            self.addr[5],
        });
    }
};

pub const EtherType = enum(u16) {
    ip = 0x0800,
    arp = 0x0806,
    ipv6 = 0x86dd,
};

pub const EtherHdr = struct {
    const Self = @This();

    const HDR_SIZE_MIN = 14;

    src: EtherAddr,
    dst: EtherAddr,
    type: EtherType,

    pub fn decode(data: []const u8) !Self {
        if (data.len < HDR_SIZE_MIN) {
            util.errorf(@src(), "too short", .{});
            return error.EtherPacketTooShort;
        }
        const type_int = std.mem.readInt(u16, data[12..14], .big);
        return Self{
            .src = EtherAddr.fromBytes(data[6..12].*),
            .dst = EtherAddr.fromBytes(data[0..6].*),
            .type = std.enums.fromInt(EtherType, type_int) orelse {
                util.errorf(@src(), "unknown type: {d}", .{type_int});
                return error.EtherUnknownType;
            },
        };
    }

    pub fn format(
        self: @This(),
        writer: *std.Io.Writer,
    ) !void {
        try writer.print("        src: {f}\n", .{self.src});
        try writer.print("        dst: {f}\n", .{self.dst});
        try writer.print("       type: {d} ({t})\n", .{ self.type, self.type });
    }
};
