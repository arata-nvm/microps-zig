const std = @import("std");

const ip = @import("ip.zig");
const util = @import("util.zig");

pub const IcmpType = enum(u8) {
    echo_reply = 0,
    dest_unreachable = 3,
    source_quench = 4,
    redirect = 5,
    echo = 8,
    time_exceeded = 11,
    parameter_problem = 12,
    timestamp = 13,
    timestamp_reply = 14,
    info_request = 15,
    info_reply = 16,
};

const IcmpBody = union(enum) {
    echo: struct { id: u16, seq: u16 },
    dest_unreachable: struct { unused: u32 },
    other: struct { dep: u32 },
};

const IcmpHdr = struct {
    const Self = @This();
    const HDR_SIZE = 4;

    typ: IcmpType,
    code: u8,
    sum: u16,
    body: IcmpBody,

    pub fn decode(data: []const u8) !Self {
        if (data.len < HDR_SIZE + 4) {
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
        return Self{
            .typ = typ,
            .code = data[1],
            .sum = std.mem.readInt(u16, data[2..4], .big),
            .body = switch (typ) {
                .echo_reply, .echo => .{ .echo = .{
                    .id = std.mem.readInt(u16, data[4..6], .big),
                    .seq = std.mem.readInt(u16, data[6..8], .big),
                } },
                .dest_unreachable => .{ .dest_unreachable = .{
                    .unused = std.mem.readInt(u32, data[4..8], .big),
                } },
                else => .{ .other = .{
                    .dep = std.mem.readInt(u32, data[4..8], .big),
                } },
            },
        };
    }

    pub fn format(
        self: Self,
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        try writer.print("       type: {d} ({t})\n", .{ self.typ, self.typ });
        try writer.print("       code: {d}\n", .{self.code});
        try writer.print("        sum: 0x{x:0>4}\n", .{self.sum});
        switch (self.body) {
            .echo => |body| {
                try writer.print("         id: {d}\n", .{body.id});
                try writer.print("        seq: {d}\n", .{body.seq});
            },
            .dest_unreachable => |body| {
                try writer.print("     unused: {d}\n", .{body.unused});
            },
            .other => |body| {
                try writer.print("        dep: {x:0>4}\n", .{body.dep});
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
    _ = iface;
    const icmp_hdr = try IcmpHdr.decode(data);
    util.debugf(@src(), "{f} => {f}, len={d}", .{ ip_hdr.src, ip_hdr.dst, data.len });
    std.debug.print("{f}", .{icmp_hdr});
}
