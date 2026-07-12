const std = @import("std");

const ip = @import("ip.zig");
const util = @import("util.zig");

const Port = struct {
    const Self = @This();

    // Dynamic Source Ports
    //  - see https://tools.ietf.org/html/rfc6335
    pub const dynamic_min = 49152;
    pub const dynamic_max = 65535;

    port: u16,

    pub fn format(
        self: @This(),
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        try writer.print("{d}", .{self.port});
    }
};

const SocketAddr = struct {
    const Self = @This();

    addr: ip.IpAddr,
    port: Port,

    pub fn fromString(s: []const u8) !Self {
        const i = std.mem.indexOfScalar(u8, s, ':') orelse return error.InvalidAddress;
        return .{
            .addr = try ip.IpAddr.fromString(s[0..i]),
            .port = .{ .port = try std.fmt.parseInt(u16, s[i + 1 ..], 10) },
        };
    }

    pub fn format(
        self: @This(),
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        try writer.print("{f}", .{self.addr});
        try writer.writeAll(":");
        try writer.print("{f}", .{self.port});
    }
};

const UdpHdr = struct {
    const Self = @This();

    const hdr_len = 8;

    src: SocketAddr,
    dst: SocketAddr,
    len: u16,
    sum: u16,

    const PseudoHdr = struct {
        const Self = @This();

        const hdr_len = 12;

        src: ip.IpAddr,
        dst: ip.IpAddr,
        zero: u8,
        proto: ip.IpProtocolType,
        len: u16,

        pub fn cksum16(self: PseudoHdr) u16 {
            var buf: [PseudoHdr.hdr_len]u8 = undefined;
            buf[0..4].* = self.src.toBytes();
            buf[4..8].* = self.dst.toBytes();
            buf[8] = self.zero;
            buf[9] = @intFromEnum(self.proto);
            std.mem.writeInt(u16, buf[10..12], self.len, .big);
            return ~util.cksum16(&buf, 0);
        }
    };

    pub fn decode(data: []const u8, ip_hdr: *const ip.IpHdr) !Self {
        if (data.len < hdr_len) {
            util.errorf(@src(), "too short", .{});
            return error.UdpTooShort;
        }
        const hdr: UdpHdr = .{
            .src = .{
                .addr = ip_hdr.src,
                .port = .{ .port = std.mem.readInt(u16, data[0..2], .big) },
            },
            .dst = .{
                .addr = ip_hdr.dst,
                .port = .{ .port = std.mem.readInt(u16, data[2..4], .big) },
            },
            .len = std.mem.readInt(u16, data[4..6], .big),
            .sum = std.mem.readInt(u16, data[6..8], .big),
        };
        if (data.len < hdr.len) {
            util.errorf(@src(), "length error: len={d} < hdr.len={d}", .{ data.len, hdr.len });
            return error.UdpLengthError;
        }
        if (hdr.sum != 0) {
            const pseudo_hdr: PseudoHdr = .{
                .src = ip_hdr.src,
                .dst = ip_hdr.dst,
                .zero = 0,
                .proto = .udp,
                .len = hdr.len,
            };
            const psum = pseudo_hdr.cksum16();
            if (util.cksum16(data[0..hdr.len], psum) != 0) {
                util.errorf(@src(), "checksum error", .{});
                return error.UdpChecksumError;
            }
        }
        return hdr;
    }

    pub fn format(
        self: @This(),
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        try writer.print("        src: {f}\n", .{self.src});
        try writer.print("        dst: {f}\n", .{self.dst});
        try writer.print("        len: {d} (payload: {d})\n", .{ self.len, self.len - hdr_len });
        try writer.print("        sum: 0x{x:0>4}\n", .{self.sum});
    }
};

pub fn init() !void {
    ip.registerProtocol(.udp, input) catch |err| {
        util.errorf(@src(), "ip.registerProtocol() failure: {t}", .{err});
        return err;
    };
}

fn input(ip_hdr: *const ip.IpHdr, data: []const u8, iface: *ip.IpIface) !void {
    const hdr = UdpHdr.decode(data, ip_hdr) catch |err| {
        util.errorf(@src(), "UdpHdr.decode() failure: {t}", .{err});
        return err;
    };
    util.debugf(@src(), "{f} => {f}, len={d}, dev={s}", .{ hdr.src, hdr.dst, data.len, iface.dev().name() });
    util.dumpf("{f}", .{hdr});
    util.debugdump(data);
}
