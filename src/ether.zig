const std = @import("std");

const util = @import("util.zig");

pub const frame_min = 60;
pub const frame_max = 1514;
pub const payload_size_min = frame_min - EtherHdr.hdr_len;
pub const payload_size_max = frame_max - EtherHdr.hdr_len;

pub const EtherAddr = struct {
    const Self = @This();

    pub const len = 6;

    addr: [len]u8,

    pub const any = Self{ .addr = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };
    pub const broadcast = Self{ .addr = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };

    pub fn fromBytes(bytes: *const [len]u8) Self {
        return Self{ .addr = bytes.* };
    }

    pub fn toBytes(self: @This()) [len]u8 {
        return self.addr;
    }

    pub fn fromString(s: []const u8) !Self {
        var parts: [len]u8 = undefined;
        var it = std.mem.splitScalar(u8, s, ':');
        for (&parts) |*p| {
            const tok = it.next() orelse return error.EtherAddrParseError;
            p.* = std.fmt.parseInt(u8, tok, 16) catch return error.EtherAddrParseError;
        }
        if (it.next() != null) return error.EtherAddrParseError;
        return fromBytes(&parts);
    }

    pub fn eql(self: Self, other: Self) bool {
        return std.mem.eql(u8, self.addr[0..], other.addr[0..]);
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

    pub const hdr_len = 14;

    src: EtherAddr,
    dst: EtherAddr,
    type: EtherType,

    pub const Decoded = struct {
        hdr: Self,
        payload: []const u8,
    };

    pub fn decode(data: []const u8) !Decoded {
        var r: std.Io.Reader = .fixed(data);
        const dst: EtherAddr = .fromBytes(try r.takeArray(EtherAddr.len));
        const src: EtherAddr = .fromBytes(try r.takeArray(EtherAddr.len));
        const type_int = try r.takeInt(u16, .big);
        return .{
            .hdr = .{
                .src = src,
                .dst = dst,
                .type = std.enums.fromInt(EtherType, type_int) orelse {
                    util.errorf(@src(), "unknown type: {d}", .{type_int});
                    return error.EtherUnknownType;
                },
            },
            .payload = r.buffered(),
        };
    }

    pub fn encode(self: Self, w: *std.Io.Writer) !void {
        try w.writeAll(&self.dst.toBytes());
        try w.writeAll(&self.src.toBytes());
        try w.writeInt(u16, @intFromEnum(self.type), .big);
    }

    pub fn format(
        self: @This(),
        writer: *std.Io.Writer,
    ) !void {
        try writer.print("        src: {f}\n", .{self.src});
        try writer.print("        dst: {f}\n", .{self.dst});
        try writer.print("       type: 0x{x:0>4} ({t})\n", .{ self.type, self.type });
    }
};
