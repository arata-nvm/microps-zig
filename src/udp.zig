const std = @import("std");

const ip = @import("ip.zig");
const util = @import("util.zig");

const Port = enum(u16) {
    _,

    // Dynamic Source Ports
    //  - see https://tools.ietf.org/html/rfc6335
    pub const dynamic_min: Port = @enumFromInt(49152);
    pub const dynamic_max: Port = @enumFromInt(65535);

    pub fn format(
        self: @This(),
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        try writer.print("{d}", .{@intFromEnum(self)});
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
            .port = @enumFromInt(try std.fmt.parseInt(u16, s[i + 1 ..], 10)),
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
    total: u16,
    sum: u16,

    const PseudoHdr = struct {
        src: ip.IpAddr,
        dst: ip.IpAddr,
        zero: u8,
        proto: ip.IpProtocolType,
        len: u16,

        const Raw = extern struct {
            src: [ip.IpAddr.len]u8,
            dst: [ip.IpAddr.len]u8,
            zero: u8,
            proto: u8,
            len: u16,
        };

        comptime {
            std.debug.assert(@sizeOf(Raw) == 12);
        }

        pub fn cksum16(self: PseudoHdr) u16 {
            const raw = Raw{
                .src = self.src.toBytes(),
                .dst = self.dst.toBytes(),
                .zero = self.zero,
                .proto = @intFromEnum(self.proto),
                .len = std.mem.nativeToBig(u16, self.len),
            };
            return ~util.cksum16(std.mem.asBytes(&raw), 0);
        }
    };

    pub const Decoded = struct {
        hdr: Self,
        payload: []const u8,
    };

    pub fn decode(data: []const u8, ip_hdr: *const ip.IpHdr) !Decoded {
        var r: std.Io.Reader = .fixed(data);
        const hdr: UdpHdr = .{
            .src = .{
                .addr = ip_hdr.src,
                .port = @enumFromInt(try r.takeInt(u16, .big)),
            },
            .dst = .{
                .addr = ip_hdr.dst,
                .port = @enumFromInt(try r.takeInt(u16, .big)),
            },
            .total = try r.takeInt(u16, .big),
            .sum = try r.takeInt(u16, .big),
        };
        if (hdr.total < hdr_len or data.len < hdr.total) {
            util.errorf(@src(), "length error: len={d}, total={d}", .{ data.len, hdr.total });
            return error.UdpLengthError;
        }
        if (hdr.sum != 0) {
            const pseudo_hdr: PseudoHdr = .{
                .src = ip_hdr.src,
                .dst = ip_hdr.dst,
                .zero = 0,
                .proto = .udp,
                .len = hdr.total,
            };
            if (util.cksum16(data[0..hdr.total], pseudo_hdr.cksum16()) != 0) {
                util.errorf(@src(), "checksum error", .{});
                return error.UdpChecksumError;
            }
        }
        return .{
            .hdr = hdr,
            .payload = data[hdr_len..hdr.total],
        };
    }

    pub fn format(
        self: @This(),
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        try writer.print("        src: {f}\n", .{self.src});
        try writer.print("        dst: {f}\n", .{self.dst});
        try writer.print("      total: {d} (payload: {d})\n", .{ self.total, self.total - hdr_len });
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
    const d = try UdpHdr.decode(data, ip_hdr);
    util.debugf(@src(), "{f} => {f}, len={d}, dev={s}", .{ d.hdr.src, d.hdr.dst, data.len, iface.dev().name() });
    util.dumpf("{f}", .{d.hdr});
    util.debugdump(data);
}
