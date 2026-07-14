const std = @import("std");

const ip = @import("ip.zig");
const platform = @import("platform.zig");
const util = @import("util.zig");

const buf_size = ip.payload_size_max;

pub const IcmpType = enum(u8) {
    echo_reply = 0,
    dest_unreachable = 3,
    echo = 8,
    _,
};

pub const IcmpDestUnreachableCode = enum(u8) {
    net_unreachable = 0,
    host_unreachable = 1,
    protocol_unreachable = 2,
    port_unreachable = 3,
    fragmentation_needed = 4,
    source_route_failed = 5,
    _,
};

const IcmpMessage = union(enum) {
    const Self = @This();

    const Echo = struct {
        id: u16,
        seq: u16,
        code: u8,
    };

    echo_reply: Echo,
    dest_unreachable: struct { code: IcmpDestUnreachableCode, unused: u32 = 0 },
    echo: Echo,
    other: IcmpType,

    pub fn typ(self: Self) IcmpType {
        return switch (self) {
            .other => |t| t,
            inline else => |_, tag| @field(IcmpType, @tagName(tag)),
        };
    }

    pub fn code(self: Self) u8 {
        return switch (self) {
            .echo, .echo_reply => |echo| echo.code,
            .dest_unreachable => |msg| @intFromEnum(msg.code),
            else => 0,
        };
    }
};

const IcmpHdr = struct {
    const Self = @This();

    sum: u16 = 0,
    msg: IcmpMessage,

    pub const Decoded = struct {
        hdr: Self,
        payload: []const u8,
    };

    pub fn decode(data: []const u8) !Decoded {
        var r: std.Io.Reader = .fixed(data);
        const type_int = try r.takeByte();
        const code_int = try r.takeByte();
        const sum = try r.takeInt(u16, .big);

        const typ: IcmpType = @enumFromInt(type_int);
        const msg: IcmpMessage = switch (typ) {
            inline .echo_reply, .echo => |t| @unionInit(IcmpMessage, @tagName(t), .{
                .id = try r.takeInt(u16, .big),
                .seq = try r.takeInt(u16, .big),
                .code = code_int,
            }),
            inline .dest_unreachable => |t| @unionInit(IcmpMessage, @tagName(t), .{
                .code = @enumFromInt(code_int),
                .unused = try r.takeInt(u32, .big),
            }),
            else => .{ .other = typ },
        };
        if (util.cksum16(data, 0) != 0) {
            util.errorf(@src(), "checksum error", .{});
            return error.IcmpChecksumError;
        }
        return .{
            .hdr = .{ .sum = sum, .msg = msg },
            .payload = r.buffered(),
        };
    }

    pub fn encode(self: Self, w: *std.Io.Writer, payload: []const u8) !void {
        const start = w.buffered().len;
        try w.writeByte(@intFromEnum(self.msg.typ()));
        try w.writeByte(self.msg.code());
        try w.writeInt(u16, 0, .big);
        switch (self.msg) {
            .echo_reply, .echo => |msg| {
                try w.writeInt(u16, msg.id, .big);
                try w.writeInt(u16, msg.seq, .big);
            },
            .dest_unreachable => |msg| {
                try w.writeInt(u32, msg.unused, .big);
            },
            .other => {
                unreachable;
            },
        }
        try w.writeAll(payload);

        const msg_bytes = w.buffered()[start..];
        std.mem.writeInt(u16, msg_bytes[2..4], util.cksum16(msg_bytes, 0), .big);
    }

    pub fn format(
        self: Self,
        writer: *std.Io.Writer,
    ) !void {
        const typ: IcmpType = self.msg.typ();
        try writer.print("       type: {d} ({s})\n", .{ typ, std.enums.tagName(IcmpType, typ) orelse "unknown" });
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
            .other => {},
        }
    }
};

pub fn init() !void {
    ip.registerProtocol(.icmp, input) catch |err| {
        util.errorf(@src(), "ip.registerProtocol() failure: err={t}", .{err});
        return error.IpRegisterProtocolFailure;
    };
}

fn input(ipd: *const ip.IpHdr.Decoded, data: []const u8, iface: *ip.IpIface) void {
    const icmpd = IcmpHdr.decode(data) catch |err| {
        util.errorf(@src(), "IcmpHdr.decode() failure: {t}", .{err});
        return;
    };
    util.debugf(@src(), "{f} => {f}, len={d}", .{ ipd.hdr.src, ipd.hdr.dst, data.len });
    util.dumpf("{f}", .{icmpd.hdr});
    util.debugdump(data);
    switch (icmpd.hdr.msg) {
        .echo => |msg| {
            // Responds with the address of the received interface.
            _ = output(.{ .echo_reply = msg }, icmpd.payload, iface.unicast, ipd.hdr.src) catch |err| {
                util.errorf(@src(), "output() failure: {t}", .{err});
            };
        },
        else => {
            // ignore
        },
    }
}

pub fn output(msg: IcmpMessage, data: []const u8, src: ip.IpAddr, dst: ip.IpAddr) !usize {
    var buf: [buf_size]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const hdr = IcmpHdr{ .msg = msg };
    hdr.encode(&w, data) catch |err| {
        util.errorf(@src(), "IcmpHdr.encode() failure: err={t}", .{err});
        return error.IcmpEncodeFailure;
    };
    const packet = w.buffered();
    util.debugf(@src(), "{f} => {f}, len={d}", .{ src, dst, packet.len });
    const d = try IcmpHdr.decode(packet);
    util.dumpf("{f}", .{d.hdr});
    return try ip.output(.icmp, packet, src, dst);
}
