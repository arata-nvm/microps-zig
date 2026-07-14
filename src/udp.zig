const std = @import("std");

const icmp = @import("icmp.zig");
const ip = @import("ip.zig");
const platform = @import("platform.zig");
const util = @import("util.zig");

const sched = platform.sched;

pub const Port = enum(u16) {
    _,

    pub const unspecified: Port = @enumFromInt(0);

    // Dynamic Source Ports
    //  - see https://tools.ietf.org/html/rfc6335
    pub const dynamic_min: Port = @enumFromInt(49152);
    pub const dynamic_max: Port = @enumFromInt(65535);
};

pub const SocketAddr = struct {
    const Self = @This();

    pub const any: Self = .{};

    addr: ip.IpAddr = .any,
    port: Port = .unspecified,

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
        try writer.print("{d}", .{self.port});
    }
};

pub const PseudoHdr = struct {
    src: ip.IpAddr,
    dst: ip.IpAddr,
    zero: u8 = 0,
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

const UdpHdr = struct {
    const Self = @This();

    const hdr_len = 8;

    src: SocketAddr,
    dst: SocketAddr,
    total: u16,
    sum: u16 = 0,

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

    pub fn encode(self: Self, w: *std.Io.Writer, data: []const u8) !void {
        const start = w.buffered().len;
        try w.writeInt(u16, @intFromEnum(self.src.port), .big);
        try w.writeInt(u16, @intFromEnum(self.dst.port), .big);
        try w.writeInt(u16, self.total, .big);
        try w.writeInt(u16, 0, .big);
        try w.writeAll(data);

        const msg_bytes = w.buffered()[start..];
        const pseudo_hdr: PseudoHdr = .{
            .src = self.src.addr,
            .dst = self.dst.addr,
            .zero = 0,
            .proto = .udp,
            .len = self.total,
        };
        const sum = util.cksum16(msg_bytes, pseudo_hdr.cksum16());
        std.mem.writeInt(u16, msg_bytes[6..8], if (sum != 0) sum else 0xffff, .big);
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
        desc: usize = 0,
        state: enum { free, open, closing } = .free,
        local: SocketAddr = .{ .addr = .any, .port = .unspecified },
        queue: util.Queue(QueueEntry) = .{},
        task: sched.Task = .{},
    };

    lock: platform.Lock = .{},
    pcbs: [size]Pcb = @splat(.{}),

    fn get(self: *Self, desc: usize) ?*Pcb {
        if (size <= desc) {
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
            if (pcb.local.addr.eql(key.addr) or pcb.local.addr.eql(.any) or key.addr.eql(.any)) {
                return desc;
            }
        }
        return null;
    }

    fn release(_: *Self, pcb: *Pcb) !void {
        const desc = pcb.desc;

        pcb.state = .closing;
        pcb.task.destroy() catch |err| switch (err) {
            error.Busy => {
                util.debugf(@src(), "pending, desc={d}", .{desc});
                pcb.task.wakeup();
                return;
            },
        };

        pcb.desc = 0;
        pcb.state = .free;
        pcb.local = .{ .addr = .any, .port = .unspecified };

        const allocator = platform.allocator();
        while (pcb.queue.pop()) |entry| {
            util.debugf(@src(), "free queue entry", .{});
            allocator.free(entry.data);
        }

        util.debugf(@src(), "success, desc={d}", .{desc});
    }

    pub fn open(self: *Self) !usize {
        self.lock.acquire();
        defer self.lock.release();

        for (&self.pcbs, 0..) |*pcb, desc| {
            if (pcb.state == .free) {
                pcb.desc = desc;
                pcb.state = .open;
                pcb.task = .{};
                return desc;
            }
        }
        return error.PcbTableFull;
    }

    pub fn close(self: *Self, desc: usize) !void {
        self.lock.acquire();
        defer self.lock.release();

        const pcb = self.get(desc) orelse return error.PcbNotFound;
        try self.release(pcb);
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
        pcb.task.wakeup();
    }

    pub fn recvfrom(self: *Self, desc: usize, buf: []u8) !RecvfromResult {
        self.lock.acquire();
        defer self.lock.release();

        const pcb = self.get(desc) orelse return error.PcbNotFound;
        while (true) {
            if (pcb.queue.pop()) |entry| {
                const allocator = platform.allocator();
                defer allocator.free(entry.data);

                util.debugf(@src(), "success, desc={d}, num={d}", .{ desc, pcb.queue.num });
                const len = @min(buf.len, entry.data.len);
                @memcpy(buf[0..len], entry.data[0..len]);
                return .{ .remote = entry.remote, .len = len };
            }

            util.debugf(@src(), "empty, desc={d}, sleep task...", .{desc});
            pcb.task.sleep(&self.lock, null) catch |err| {
                util.debugf(@src(), "interrupted: {t}", .{err});
                return error.Interrupted;
            };

            util.debugf(@src(), "task wakeup", .{});

            if (pcb.state == .closing) {
                util.debugf(@src(), "closed", .{});
                try self.release(pcb);
                return error.PcbClosed;
            }
        }
    }

    pub fn sendto(self: *Self, desc: usize, data: []const u8, remote: SocketAddr) !usize {
        self.lock.acquire();
        defer self.lock.release();

        const pcb = self.get(desc) orelse return error.PcbNotFound;
        const local = self.resolveLocal(pcb, remote);
        util.debugf(@src(), "resolve local address, addr={f}", .{local});

        return try output(local, remote, data);
    }

    fn resolveLocal(self: *Self, pcb: *Pcb, remote: SocketAddr) !SocketAddr {
        var local = pcb.local;
        if (local.addr.eql(.any)) {
            const iface = ip.route.getIface(remote.addr) orelse {
                util.errorf(@src(), "iface not found that can reach foreign address, addr={f}", .{remote.addr});
                return error.PcbNoRoute;
            };
            local.addr = iface.unicast;
        }
        if (local.port == .unspecified) {
            local.port = try self.allocPort(local.addr);
            pcb.local.port = local.port; // save dynamic source port
        }
        return local;
    }

    fn allocPort(self: *Self, local: ip.IpIface) !Port {
        const min: u32 = @intFromEnum(Port.dynamic_min);
        const max: u32 = @intFromEnum(Port.dynamic_max);
        for (min..max + 1) |p| {
            const port: Port = @enumFromInt(p);
            local.port = port;
            if (self.select(local) == null) {
                util.debugf(@src(), "dynamic assign local port, port={d}", .{port});
                return port;
            }
        }

        util.debugf(@src(), "failed to dynamic assign local port, addr={f}", .{local.addr});
        return error.PcbNoAvailablePort;
    }
};

pub const RecvfromResult = struct {
    remote: SocketAddr,
    len: usize,
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

    pcb_table.deliver(udpd.hdr.dst, udpd.hdr.src, udpd.payload) catch |err| {
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

fn output(src: SocketAddr, dst: SocketAddr, data: []const u8) !usize {
    var buf: [ip.payload_size_max]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const hdr = UdpHdr{
        .src = src,
        .dst = dst,
        .total = @intCast(UdpHdr.hdr_len + data.len),
    };
    hdr.encode(&w, data) catch |err| {
        util.errorf(@src(), "UdpHdr.encode() failure: {t}", .{err});
        return err;
    };
    util.debugf(@src(), "{f} => {f}, len={d}", .{ src, dst, hdr.total });
    util.dumpf("{f}", .{hdr});
    util.debugdump(w.buffered());
    _ = ip.output(.udp, w.buffered(), src.addr, dst.addr) catch |err| {
        util.errorf(@src(), "ip.output() failure: {t}", .{err});
        return err;
    };
    return data.len;
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

    pub fn recvfrom(desc: usize, buf: []u8) !RecvfromResult {
        return pcb_table.recvfrom(desc, buf) catch |err| {
            util.errorf(@src(), "pcb_table.recvfrom() failure: {t}", .{err});
            return err;
        };
    }

    pub fn sendto(desc: usize, data: []const u8, remote: SocketAddr) !usize {
        return pcb_table.sendto(desc, data, remote) catch |err| {
            util.errorf(@src(), "pcb_table.sendto() failure: {t}", .{err});
            return err;
        };
    }
};
