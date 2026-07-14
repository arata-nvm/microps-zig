const std = @import("std");

const device = @import("device.zig");
const ether = @import("ether.zig");
const ip = @import("ip.zig");
const net = @import("net.zig");
const platform = @import("platform.zig");
const util = @import("util.zig");

// Hardware Types
//  - see https://www.iana.org/assignments/arp-parameters/arp-parameters.txt
const ArpHrd = enum(u16) {
    ether = 1,
};

const ArpPro = enum(u16) {
    ip = @intFromEnum(ether.EtherType.ip),
};

const ArpOp = enum(u16) {
    request = 1,
    reply = 2,
    _,
};

const ArpHdr = struct {
    const Self = @This();

    const hdr_len = 8;

    hrd: ArpHrd,
    pro: ArpPro,
    hln: u8,
    pln: u8,
    op: ArpOp,

    pub fn decode(r: *std.Io.Reader) !Self {
        const hrd = try r.takeInt(u16, .big);
        const pro = try r.takeInt(u16, .big);
        const hln = try r.takeByte();
        const pln = try r.takeByte();
        const op = try r.takeInt(u16, .big);
        const self = Self{
            .hrd = std.enums.fromInt(ArpHrd, hrd) orelse {
                util.errorf(@src(), "unknown arp hrd: {d}", .{hrd});
                return error.ArpUnknownHrd;
            },
            .pro = std.enums.fromInt(ArpPro, pro) orelse {
                util.errorf(@src(), "unknown arp pro: {d}", .{pro});
                return error.ArpUnknownPro;
            },
            .hln = hln,
            .pln = pln,
            .op = @enumFromInt(op),
        };
        if (self.hrd != .ether or self.hln != ether.EtherAddr.len) {
            util.errorf(@src(), "unsupported hardware address", .{});
            return error.ArpUnsupportedHrd;
        }
        if (self.pro != .ip or self.pln != ip.IpAddr.len) {
            util.errorf(@src(), "unsupported protocol address", .{});
            return error.ArpUnsupportedPro;
        }
        return self;
    }

    pub fn encode(self: Self, w: *std.Io.Writer) !void {
        try w.writeInt(u16, @intFromEnum(self.hrd), .big);
        try w.writeInt(u16, @intFromEnum(self.pro), .big);
        try w.writeByte(self.hln);
        try w.writeByte(self.pln);
        try w.writeInt(u16, @intFromEnum(self.op), .big);
    }

    pub fn format(
        self: Self,
        writer: *std.Io.Writer,
    ) !void {
        try writer.print("        hrd: 0x{x:0>4} ({t})\n", .{ @intFromEnum(self.hrd), self.hrd });
        try writer.print("        pro: 0x{x:0>4} ({t})\n", .{ @intFromEnum(self.pro), self.pro });
        try writer.print("        hln: {d}\n", .{self.hln});
        try writer.print("        pln: {d}\n", .{self.pln});
        try writer.print("         op: {d} ({s})\n", .{ @intFromEnum(self.op), std.enums.tagName(ArpOp, self.op) orelse "unknown" });
    }
};

const ArpEtherIp = struct {
    const Self = @This();

    const msg_len = ArpHdr.hdr_len + ether.EtherAddr.len * 2 + ip.IpAddr.len * 2;

    hdr: ArpHdr,
    sha: ether.EtherAddr,
    spa: ip.IpAddr,
    tha: ether.EtherAddr,
    tpa: ip.IpAddr,

    pub fn init(op: ArpOp, sha: ether.EtherAddr, spa: ip.IpAddr, tha: ether.EtherAddr, tpa: ip.IpAddr) Self {
        return Self{
            .hdr = .{
                .hrd = .ether,
                .pro = .ip,
                .hln = ether.EtherAddr.len,
                .pln = ip.IpAddr.len,
                .op = op,
            },
            .sha = sha,
            .spa = spa,
            .tha = tha,
            .tpa = tpa,
        };
    }

    pub fn decode(data: []const u8) !Self {
        var r: std.Io.Reader = .fixed(data);
        return Self{
            .hdr = try ArpHdr.decode(&r),
            .sha = .fromBytes(try r.takeArray(ether.EtherAddr.len)),
            .spa = .fromBytes(try r.takeArray(ip.IpAddr.len)),
            .tha = .fromBytes(try r.takeArray(ether.EtherAddr.len)),
            .tpa = .fromBytes(try r.takeArray(ip.IpAddr.len)),
        };
    }

    pub fn encode(self: Self, w: *std.Io.Writer) !void {
        try self.hdr.encode(w);
        try w.writeAll(&self.sha.toBytes());
        try w.writeAll(&self.spa.toBytes());
        try w.writeAll(&self.tha.toBytes());
        try w.writeAll(&self.tpa.toBytes());
    }

    pub fn format(
        self: Self,
        writer: *std.Io.Writer,
    ) !void {
        try writer.print("{f}", .{self.hdr});
        try writer.print("        sha: {f}\n", .{self.sha});
        try writer.print("        spa: {f}\n", .{self.spa});
        try writer.print("        tha: {f}\n", .{self.tha});
        try writer.print("        tpa: {f}\n", .{self.tpa});
    }
};

const ArpCache = struct {
    const Self = @This();

    const cache_size = 32;
    const timeout_sec = 30;

    const Entry = struct {
        pa: ip.IpAddr,
        timestamp: std.Io.Timestamp,
        state: union(enum) {
            incomplete: void,
            resolved: ether.EtherAddr,
            static: ether.EtherAddr,
        },
    };

    const ResolveResult = union(enum) {
        miss: void,
        waiting: void,
        resolved: ether.EtherAddr,
    };

    lock: platform.Lock = .{},
    entries: [cache_size]?Entry = @splat(null),

    pub fn insert(self: *Self, pa: ip.IpAddr, ha: ether.EtherAddr, now: std.Io.Timestamp) void {
        util.debugf(@src(), "INSERT: pa={f}, ha={f}", .{ pa, ha });
        self.lock.acquire();
        defer self.lock.release();

        const entry = self.allocSlot();
        entry.* = .{
            .pa = pa,
            .timestamp = now,
            .state = .{ .resolved = ha },
        };
    }

    pub fn update(self: *Self, pa: ip.IpAddr, ha: ether.EtherAddr, now: std.Io.Timestamp) bool {
        util.debugf(@src(), "UPDATE: pa={f}, ha={f}", .{ pa, ha });
        self.lock.acquire();
        defer self.lock.release();

        const entry = self.findSlot(pa) orelse return false;
        if (entry.state == .static) {
            return true;
        }
        entry.timestamp = now;
        entry.state = .{ .resolved = ha };
        return true;
    }

    pub fn resolve(self: *Self, pa: ip.IpAddr, now: std.Io.Timestamp) ResolveResult {
        self.lock.acquire();
        defer self.lock.release();

        if (self.findSlot(pa)) |entry| {
            return switch (entry.state) {
                .incomplete => .waiting,
                .resolved => |addr| .{ .resolved = addr },
                .static => |addr| .{ .resolved = addr },
            };
        }

        util.debugf(@src(), "cache not found, pa={f}", .{pa});
        const entry = self.allocSlot();
        entry.* = .{
            .pa = pa,
            .timestamp = now,
            .state = .incomplete,
        };
        return .miss;
    }

    pub fn removeExpired(self: *Self, now: std.Io.Timestamp) void {
        self.lock.acquire();
        defer self.lock.release();

        for (&self.entries) |*entry| {
            const e = entry.* orelse continue;
            if (e.state == .static) {
                continue;
            }
            if (e.timestamp.durationTo(now).toSeconds() > timeout_sec) {
                switch (e.state) {
                    .incomplete => {
                        util.debugf(@src(), "DELETE: pa={f}, state={t}", .{ e.pa, e.state });
                    },
                    .resolved, .static => |ha| {
                        util.debugf(@src(), "DELETE: pa={f}, ha={t} ({f})", .{ e.pa, e.state, ha });
                    },
                }
                entry.* = null;
            }
        }
    }

    fn allocSlot(self: *Self) *?Entry {
        var oldest = &self.entries[0];
        for (&self.entries) |*entry| {
            const e = entry.* orelse {
                return entry;
            };
            if (e.state == .static) {
                continue;
            }
            const o = oldest.* orelse {
                oldest = entry;
                continue;
            };
            if (e.timestamp.nanoseconds < o.timestamp.nanoseconds) {
                oldest = entry;
            }
        }
        return oldest;
    }

    fn findSlot(self: *Self, pa: ip.IpAddr) ?*Entry {
        for (&self.entries) |*entry| {
            if (entry.*) |*e| {
                if (e.pa.eql(pa)) {
                    return e;
                }
            }
        }
        return null;
    }
};

var cache: ArpCache = .{};

pub fn init() !void {
    net.register(.arp, input) catch |err| {
        util.errorf(@src(), "net.register() failure: {t}", .{err});
        return err;
    };
    platform.timer.register(.fromSeconds(1), timer) catch |err| {
        util.errorf(@src(), "platform.timer.register() failure: {t}", .{err});
        return err;
    };
}

fn input(data: []const u8, dev: *device.Device) void {
    const msg = ArpEtherIp.decode(data) catch |err| {
        util.errorf(@src(), "ArpEtherIp.decde() failure: {t}", .{err});
        return;
    };
    util.debugf(@src(), "dev={s}, len={d}", .{ dev.name(), data.len });
    util.dumpf("{f}", .{msg});
    util.debugdump(data);

    const now = platform.now();
    const merged = cache.update(msg.spa, msg.sha, now);
    const iface = dev.getIface(ip.IpIface) orelse return;
    if (iface.unicast.eql(msg.tpa)) {
        if (!merged) {
            cache.insert(msg.spa, msg.sha, now);
        }
        if (msg.hdr.op == .request) {
            reply(iface, msg.sha, msg.spa, msg.sha) catch |err| {
                util.errorf(@src(), "reply() failure: {t}", .{err});
                return;
            };
        }
    }
}

fn request(iface: *ip.IpIface, tpa: ip.IpAddr) !void {
    const msg = ArpEtherIp.init(
        .request,
        ether.EtherAddr.fromBytes(iface.dev().addr[0..ether.EtherAddr.len]),
        iface.unicast,
        ether.EtherAddr.any,
        tpa,
    );
    util.debugf(@src(), "dev={s}, len={d}", .{ iface.dev().name(), ArpEtherIp.msg_len });
    util.dumpf("{f}", .{msg});

    var buf: [ArpEtherIp.msg_len]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try msg.encode(&w);
    util.debugdump(w.buffered());
    return iface.dev().output(.arp, w.buffered(), &iface.dev().broadcast);
}

fn reply(iface: *ip.IpIface, tha: ether.EtherAddr, tpa: ip.IpAddr, dst: ether.EtherAddr) !void {
    const msg = ArpEtherIp.init(
        .reply,
        ether.EtherAddr.fromBytes(iface.dev().addr[0..ether.EtherAddr.len]),
        iface.unicast,
        tha,
        tpa,
    );
    util.debugf(@src(), "dev={s}, len={d}", .{ iface.dev().name(), ArpEtherIp.msg_len });
    util.dumpf("{f}", .{msg});

    var buf: [ArpEtherIp.msg_len]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try msg.encode(&w);
    util.debugdump(w.buffered());
    return iface.dev().output(.arp, w.buffered(), &dst.toBytes());
}

pub fn resolve(iface: *ip.IpIface, pa: ip.IpAddr) !ether.EtherAddr {
    if (iface.dev().type != .ethernet) {
        util.debugf(@src(), "unsupported hardware address type", .{});
        return error.ArpUnsupportedHrd;
    }

    const now = platform.now();
    switch (cache.resolve(pa, now)) {
        .miss, .waiting => {
            request(iface, pa) catch |err| {
                util.errorf(@src(), "request() failure: {t}", .{err});
            };
            return error.ArpResolveWaiting;
        },
        .resolved => |ha| {
            util.debugf(@src(), "resolved, pa={f}, ha={f}", .{ pa, ha });
            return ha;
        },
    }
}

fn timer() void {
    const now = platform.now();
    cache.removeExpired(now);
}
