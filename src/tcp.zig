const std = @import("std");

const ip = @import("ip.zig");
const platform = @import("platform.zig");
const udp = @import("udp.zig");
const util = @import("util.zig");

const TcpFlag = packed struct(u8) {
    fin: u1,
    syn: u1,
    rst: u1,
    psh: u1,
    ack: u1,
    urg: u1,
    zero: u2,

    pub fn format(
        self: @This(),
        writer: *std.Io.Writer,
    ) !void {
        try writer.print("{c}{c}{c}{c}{c}{c}", .{
            @as(u8, if (self.urg != 0) 'U' else '-'),
            @as(u8, if (self.ack != 0) 'A' else '-'),
            @as(u8, if (self.psh != 0) 'P' else '-'),
            @as(u8, if (self.rst != 0) 'R' else '-'),
            @as(u8, if (self.syn != 0) 'S' else '-'),
            @as(u8, if (self.fin != 0) 'F' else '-'),
        });
    }
};

const TcpOptionKind = enum(u8) {
    end_of_option_list = 0,
    no_operation = 1,
    maximum_segment_size = 2,
    window_scale = 3,
    sack_permitted = 4,
    sack = 5,
    timestamps = 8,
    unknown,
};

const TcpOption = union(TcpOptionKind) {
    end_of_option_list: void,
    no_operation: void,
    maximum_segment_size: struct { mss: u16 },
    window_scale: void,
    sack_permitted: void,
    sack: void,
    timestamps: void,
    unknown: struct { kind: u8, len: u8 },
};

const TcpHdr = struct {
    const Self = @This();

    const hdr_len_min = 20;

    src: udp.SocketAddr,
    dst: udp.SocketAddr,
    seq: u32,
    ack: u32,
    off: u4,
    flg: TcpFlag,
    wnd: u16,
    sum: u16,
    up: u16,
    opts: std.ArrayList(TcpOption) = .empty,

    pub const Decoded = struct {
        hdr: Self,
        payload: []const u8,
    };

    pub fn decode(data: []const u8, ip_hdr: *const ip.IpHdr) !Decoded {
        var r: std.Io.Reader = .fixed(data);
        var hdr: TcpHdr = .{
            .src = .{
                .addr = ip_hdr.src,
                .port = @enumFromInt(try r.takeInt(u16, .big)),
            },
            .dst = .{
                .addr = ip_hdr.dst,
                .port = @enumFromInt(try r.takeInt(u16, .big)),
            },
            .seq = try r.takeInt(u32, .big),
            .ack = try r.takeInt(u32, .big),
            .off = @truncate(try r.takeInt(u8, .big) >> 4),
            .flg = @bitCast(try r.takeInt(u8, .big)),
            .wnd = try r.takeInt(u16, .big),
            .sum = try r.takeInt(u16, .big),
            .up = try r.takeInt(u16, .big),
        };

        const allocator = platform.allocator();
        while (r.seek < hdr.hlen()) {
            const opt: TcpOption = switch (try r.takeInt(u8, .big)) {
                0 => break,
                1 => .{ .no_operation = {} },
                2 => blk: {
                    const len = try r.takeInt(u8, .big);
                    if (len != 4) {
                        util.errorf(@src(), "invalid TCP option length: kind=2, len={d}", .{len});
                        return error.TcpOptionLengthError;
                    }
                    const mss = try r.takeInt(u16, .big);
                    break :blk .{ .maximum_segment_size = .{ .mss = mss } };
                },
                3 => blk: {
                    const len = try r.takeInt(u8, .big);
                    if (len != 3) {
                        util.errorf(@src(), "invalid TCP option length: kind=3, len={d}", .{len});
                        return error.TcpOptionLengthError;
                    }
                    _ = try r.take(1);
                    break :blk .{ .window_scale = {} };
                },
                4 => blk: {
                    const len = try r.takeInt(u8, .big);
                    if (len != 2) {
                        util.errorf(@src(), "invalid TCP option length: kind=4, len={d}", .{len});
                        return error.TcpOptionLengthError;
                    }
                    break :blk .{ .sack_permitted = {} };
                },
                5 => blk: {
                    const len = try r.takeInt(u8, .big);
                    if (len < 2) {
                        util.errorf(@src(), "invalid TCP option length: kind=5, len={d}", .{len});
                        return error.TcpOptionLengthError;
                    }
                    _ = try r.take(len - 2);
                    break :blk .{ .sack = {} };
                },
                8 => blk: {
                    const len = try r.takeInt(u8, .big);
                    if (len != 10) {
                        util.errorf(@src(), "invalid TCP option length: kind=8, len={d}", .{len});
                        return error.TcpOptionLengthError;
                    }
                    _ = try r.take(8);
                    break :blk .{ .timestamps = {} };
                },
                else => |kind| blk: {
                    const len = try r.takeInt(u8, .big);
                    _ = try r.take(len - 2);
                    break :blk .{ .unknown = .{ .kind = kind, .len = len } };
                },
            };
            try hdr.opts.append(allocator, opt);
        }

        const pseudo_hdr: udp.PseudoHdr = .{
            .src = ip_hdr.src,
            .dst = ip_hdr.dst,
            .proto = .tcp,
            .len = @intCast(data.len),
        };
        if (util.cksum16(data, pseudo_hdr.cksum16()) != 0) {
            util.errorf(@src(), "checksum error", .{});
            return error.TcpChecksumError;
        }

        return .{
            .hdr = hdr,
            .payload = data[hdr.hlen()..],
        };
    }

    pub fn hlen(self: Self) u8 {
        return @as(u8, self.off) << 2;
    }

    pub fn format(
        self: @This(),
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        try writer.print("        src: {f}\n", .{self.src});
        try writer.print("        dst: {f}\n", .{self.dst});
        try writer.print("        seq: {d}\n", .{self.seq});
        try writer.print("        ack: {d}\n", .{self.ack});
        try writer.print("        off: 0x{x:0>2} ({d}) (options: {d})\n", .{ self.off, self.hlen(), self.hlen() - hdr_len_min });
        try writer.print("        flg: 0x{x:0>2} ({f})\n", .{ @as(u8, @bitCast(self.flg)), self.flg });
        try writer.print("        wnd: {d}\n", .{self.wnd});
        try writer.print("        sum: 0x{x:0>4}\n", .{self.sum});
        try writer.print("         up: {d}\n", .{self.up});
        for (self.opts.items, 0..) |opt, i| {
            const tag = std.meta.activeTag(opt);
            switch (opt) {
                .unknown => |o| {
                    try writer.print("     opt[{d}]: kind={d}, len={d}\n", .{ i, o.kind, o.len });
                },
                else => {
                    try writer.print("     opt[{d}]: kind={d} ({t})\n", .{ i, tag, tag });
                },
            }
        }
    }
};

pub fn init() !void {
    ip.registerProtocol(.tcp, input) catch |err| {
        util.errorf(@src(), "ip.registerProtocol() failure: {t}", .{err});
        return err;
    };
}

pub fn input(ipd: *const ip.IpHdr.Decoded, data: []const u8, iface: *ip.IpIface) !void {
    const tcpd = try TcpHdr.decode(data, &ipd.hdr);

    const src_is_broadcast = tcpd.hdr.src.addr.eql(ip.IpAddr.broadcast) or tcpd.hdr.src.addr.eql(iface.broadcast);
    const dst_is_broadcast = tcpd.hdr.dst.addr.eql(ip.IpAddr.broadcast) or tcpd.hdr.dst.addr.eql(iface.broadcast);
    if (src_is_broadcast or dst_is_broadcast) {
        util.errorf(@src(), "only supports unicast, src={f}, dst={f}", .{ tcpd.hdr.src, tcpd.hdr.dst });
        return error.TcpUnicastOnly;
    }

    util.debugf(@src(), "{f} => {f}, len={d}, dev={s}", .{ tcpd.hdr.src, tcpd.hdr.dst, data.len, iface.dev().name() });
    util.dumpf("{f}", .{tcpd.hdr});
    util.debugdump(data);
}
