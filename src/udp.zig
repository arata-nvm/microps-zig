const std = @import("std");

const icmp = @import("icmp.zig");
const ip = @import("ip.zig");
const platform = @import("platform.zig");
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

pub const SocketAddr = struct {
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

const PcbTable = struct {
    const Self = @This();

    const size = 16;

    const QueueEntry = struct {
        remote: SocketAddr,
        data: []const u8,
    };

    const Pcb = struct {
        state: enum { free, open, closing } = .free,
        local: SocketAddr = .{ .addr = ip.IpAddr.any, .port = @enumFromInt(0) },
        queue: util.Queue(QueueEntry) = .{},
    };

    lock: platform.Lock = .{},
    pcbs: [size]Pcb = @splat(.{}),

    fn get(self: *Self, desc: usize) ?*Pcb {
        if (size < desc) {
            return null;
        }
        const pcb = &self.pcbs[desc];
        return if (pcb.state == .open) pcb else null;
    }

    fn select(self: *Self, key: SocketAddr) ?usize {
        for (&self.pcbs, 0..) |*pcb, desc| {
            if (pcb.state != .open) {
                continue;
            }
            if (pcb.local.port != key.port) {
                continue;
            }
            if (pcb.local.addr.eql(key.addr) or pcb.local.addr.eql(ip.IpAddr.any) or key.addr.eql(ip.IpAddr.any)) {
                return desc;
            }
        }
        return null;
    }

    pub fn open(self: *Self) !usize {
        self.lock.acquire();
        defer self.lock.release();

        for (&self.pcbs, 0..) |*pcb, desc| {
            if (pcb.state == .free) {
                pcb.state = .open;
                return desc;
            }
        }
        return error.PcbTableFull;
    }

    pub fn close(self: *Self, desc: usize) !void {
        self.lock.acquire();
        defer self.lock.release();

        const pcb = self.get(desc) orelse return error.PcbNotFound;
        pcb.state = .free;
        pcb.local = .{ .addr = ip.IpAddr.any, .port = @enumFromInt(0) };

        const allocator = platform.allocator();
        while (pcb.queue.pop()) |entry| {
            util.debugf(@src(), "free queue entry", .{});
            allocator.free(entry.data);
        }
    }

    pub fn bind(self: *Self, desc: usize, local: SocketAddr) !void {
        self.lock.acquire();
        defer self.lock.release();

        const pcb = self.get(desc) orelse return error.PcbNotFound;
        if (self.select(local)) |exist_desc| {
            const exist = self.get(exist_desc).?;
            util.errorf(@src(), "already in use, desc={d}, want={f}, exist={f}", .{ desc, local, exist.local });
            return error.PcbAlreadyInUse;
        }
        pcb.local = local;
    }

    pub fn deliver(self: *Self, dst: SocketAddr, src: SocketAddr, data: []const u8) !void {
        self.lock.acquire();
        defer self.lock.release();

        const desc = self.select(dst) orelse return error.PcbNotInUse;
        const pcb = self.get(desc) orelse return error.PcbNotFound;
        const allocator = platform.allocator();
        try pcb.queue.push(.{
            .remote = src,
            .data = try allocator.dupe(u8, data),
        });
        util.debugf(@src(), "success, desc={d}, num={d}", .{ desc, pcb.queue.num });
    }
};

var pcb_table: PcbTable = .{};

pub fn init() !void {
    ip.registerProtocol(.udp, input) catch |err| {
        util.errorf(@src(), "ip.registerProtocol() failure: {t}", .{err});
        return err;
    };
}

fn input(ipd: *const ip.IpHdr.Decoded, data: []const u8, iface: *ip.IpIface) !void {
    const udpd = try UdpHdr.decode(data, &ipd.hdr);
    util.debugf(@src(), "{f} => {f}, len={d}, dev={s}", .{ udpd.hdr.src, udpd.hdr.dst, data.len, iface.dev().name() });
    util.dumpf("{f}", .{udpd.hdr});
    util.debugdump(data);

    pcb_table.deliver(udpd.hdr.dst, udpd.hdr.src, data) catch |err| {
        util.errorf(@src(), "pcb_table.deliver() failure: {t}", .{err});
        _ = try icmp.output(
            .{ .dest_unreachable = .{ .code = .port_unreachable } },
            ipd.raw[0 .. ipd.hdr.hlen() + 8],
            iface.unicast,
            ipd.hdr.src,
        );
        return err;
    };
}

pub const cmd = struct {
    pub fn open() !usize {
        const desc = pcb_table.open() catch |err| {
            util.errorf(@src(), "pcb_table.open() failure: {t}", .{err});
            return err;
        };
        util.debugf(@src(), "desc={d}", .{desc});
        return desc;
    }

    pub fn close(desc: usize) !void {
        pcb_table.close(desc) catch |err| {
            util.errorf(@src(), "pcb_table.close() failure: {t}", .{err});
            return err;
        };
        util.debugf(@src(), "desc={d}", .{desc});
    }

    pub fn bind(desc: usize, local: SocketAddr) !void {
        pcb_table.bind(desc, local) catch |err| {
            util.errorf(@src(), "pcb_table.bind() failure: {t}", .{err});
            return err;
        };
        util.debugf(@src(), "desc={d}, {f}", .{ desc, local });
    }
};
