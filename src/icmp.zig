const std = @import("std");

const ip = @import("ip.zig");
const platform = @import("platform/linux/platform.zig");
const util = @import("util.zig");

const ICMP_BUFSIZ = ip.IP_PAYLOAD_SIZE_MAX;

pub const IcmpType = enum(u8) {
    echo_reply = 0,
    dest_unreachable = 3,
    echo = 8,
};

pub const IcmpDestUnreachableCode = enum(u8) {
    net_unreachable = 0,
    host_unreachable = 1,
    protocol_unreachable = 2,
    port_unreachable = 3,
    fragmentation_needed = 4,
    source_route_failed = 5,
};

const IcmpMessage = union(IcmpType) {
    const Self = @This();

    const Echo = struct {
        id: u16,
        seq: u16,
    };

    echo_reply: Echo,
    dest_unreachable: struct { code: IcmpDestUnreachableCode, unused: u32 = 0 },
    echo: Echo,

    pub fn code(self: Self) u8 {
        return switch (self) {
            .dest_unreachable => |msg| @intFromEnum(msg.code),
            else => 0,
        };
    }
};

const IcmpHdr = struct {
    const Self = @This();
    const HDR_SIZE_MIN = 8;

    sum: u16 = 0,
    msg: IcmpMessage,

    pub fn decode(data: []const u8) !Self {
        if (data.len < HDR_SIZE_MIN) {
            util.errorf(@src(), "too short", .{});
            return error.IpPacketTooShort;
        }
        if (util.cksum16(data, 0) != 0) {
            util.errorf(@src(), "checksum error", .{});
            return error.IcmpChecksumError;
        }

        const typ: IcmpType = std.enums.fromInt(IcmpType, data[0]) orelse {
            util.errorf(@src(), "unknown type: {d}", .{data[0]});
            return error.IcmpUnknownType;
        };
        const msg: IcmpMessage = switch (typ) {
            inline .echo_reply, .echo => |t| @unionInit(IcmpMessage, @tagName(t), .{
                .id = std.mem.readInt(u16, data[4..6], .big),
                .seq = std.mem.readInt(u16, data[6..8], .big),
            }),
            inline .dest_unreachable => |t| @unionInit(IcmpMessage, @tagName(t), .{
                .code = std.enums.fromInt(IcmpDestUnreachableCode, data[1]) orelse {
                    util.errorf(@src(), "unknown dest_unreachable code: {d}", .{data[1]});
                    return error.IcmpUnknownDestUnreachableCode;
                },
                .unused = std.mem.readInt(u32, data[4..8], .big),
            }),
        };
        return Self{
            .sum = std.mem.readInt(u16, data[2..4], .big),
            .msg = msg,
        };
    }

    pub fn encode(self: *Self, buf: []u8, payload: []const u8) ![]const u8 {
        const msg_size = IcmpHdr.HDR_SIZE_MIN + payload.len;
        if (buf.len < msg_size) {
            util.errorf(@src(), "buffer too short: len={d} < msg_size={d}", .{ buf.len, msg_size });
            return error.IpBufferTooShort;
        }

        buf[0] = @intFromEnum(self.msg);
        std.mem.writeInt(u8, buf[1..2], self.msg.code(), .big);
        std.mem.writeInt(u16, buf[2..4], 0, .big);
        switch (self.msg) {
            .echo_reply, .echo => |msg| {
                std.mem.writeInt(u16, buf[4..6], msg.id, .big);
                std.mem.writeInt(u16, buf[6..8], msg.seq, .big);
            },
            .dest_unreachable => |msg| {
                std.mem.writeInt(u32, buf[4..8], msg.unused, .big);
            },
        }
        @memcpy(buf[IcmpHdr.HDR_SIZE_MIN..msg_size], payload);

        self.sum = util.cksum16(buf[0..msg_size], 0);
        std.mem.writeInt(u16, buf[2..4], self.sum, .big);
        return buf[0..msg_size];
    }

    pub fn format(
        self: Self,
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        const typ: IcmpType = self.msg;
        try writer.print("       type: {d} ({t})\n", .{ typ, typ });
        try writer.print("       code: {d}\n", .{self.msg.code()});
        try writer.print("        sum: 0x{x:0>4}\n", .{self.sum});
        switch (self.msg) {
            .echo_reply, .echo => |msg| {
                try writer.print("         id: {d}\n", .{msg.id});
                try writer.print("        seq: {d}\n", .{msg.seq});
            },
            .dest_unreachable => |msg| {
                try writer.print("     unused: {d}\n", .{msg.unused});
            },
        }
    }
};

pub fn init() !void {
    ip.registerProtocol(.icmp, input) catch |err| {
        util.errorf(@src(), "ip.registerProtocol() failure: err={t}", .{err});
        return error.IpRegisterProtocolFailure;
    };
}

fn input(ip_hdr: *const ip.IpHdr, data: []const u8, iface: *ip.IpIface) !void {
    const icmp_hdr = try IcmpHdr.decode(data);
    util.debugf(@src(), "{f} => {f}, len={d}", .{ ip_hdr.src, ip_hdr.dst, data.len });
    std.debug.print("{f}", .{icmp_hdr});
    switch (icmp_hdr.msg) {
        .echo => |msg| {
            // Responds with the address of the received interface.
            _ = try output(.{ .echo_reply = msg }, data[IcmpHdr.HDR_SIZE_MIN..], iface.unicast, ip_hdr.src);
        },
        else => {
            // ignore
        },
    }
}

pub fn output(msg: IcmpMessage, data: []const u8, src: ip.IpAddr, dst: ip.IpAddr) !usize {
    var buf: [ICMP_BUFSIZ]u8 = undefined;
    var hdr = IcmpHdr{ .msg = msg };
    const packet = hdr.encode(&buf, data) catch |err| {
        util.errorf(@src(), "IcmpHdr.encode() failure: err={t}", .{err});
        return error.IcmpEncodeFailure;
    };
    util.debugf(@src(), "{f} => {f}, len={d}", .{ src, dst, packet.len });
    std.debug.print("{f}", .{hdr});
    return try ip.output(.icmp, packet, src, dst);
}
