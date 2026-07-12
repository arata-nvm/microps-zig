const std = @import("std");

const arp = @import("arp.zig");
const device = @import("device.zig");
const icmp = @import("icmp.zig");
const net = @import("net.zig");
const platform = @import("platform.zig");
const util = @import("util.zig");

const version_v4 = 4;

const total_size_max = std.math.maxInt(u16);
pub const payload_size_max = total_size_max - IpHdr.hdr_len_min;

const IpHdrFlags = packed struct(u3) {
    const Self = @This();

    mf: bool = false,
    df: bool = false,
    rf: bool = false,

    pub fn format(
        self: Self,
        writer: *std.Io.Writer,
    ) !void {
        try writer.print("{x}", .{@as(u3, @bitCast(self))});
    }
};

pub const IpAddr = struct {
    const Self = @This();

    pub const len = 4;

    addr: u32,

    pub const any = IpAddr{ .addr = 0x00000000 };
    pub const broadcast = IpAddr{ .addr = 0xffffffff };

    pub fn fromBytes(bytes: *const [len]u8) IpAddr {
        return IpAddr{ .addr = std.mem.readInt(u32, bytes, .big) };
    }

    pub fn toBytes(self: Self) [len]u8 {
        var bytes: [len]u8 = undefined;
        std.mem.writeInt(u32, bytes[0..], self.addr, .big);
        return bytes;
    }

    pub fn fromString(s: []const u8) !IpAddr {
        var parts: [4]u8 = undefined;
        var it = std.mem.splitScalar(u8, s, '.');
        for (&parts) |*p| {
            const tok = it.next() orelse return error.IpAddrParseError;
            p.* = std.fmt.parseInt(u8, tok, 10) catch return error.IpAddrParseError;
        }
        if (it.next() != null) return error.IpAddrParseError;
        return fromBytes(&parts);
    }

    pub fn eql(self: Self, other: Self) bool {
        return self.addr == other.addr;
    }

    pub fn isSameSubnet(self: Self, other: Self, netmask: Self) bool {
        return (self.addr & netmask.addr) == (other.addr & netmask.addr);
    }

    pub fn isInSubnet(self: Self, other: Self, netmask: Self) bool {
        return (self.addr & netmask.addr) == other.addr;
    }

    pub fn isLessSpecificThan(self: Self, other: Self) bool {
        return self.addr < other.addr;
    }

    pub fn masked(self: Self, netmask: Self) Self {
        return IpAddr{ .addr = self.addr & netmask.addr };
    }

    pub fn format(self: Self, writer: *std.Io.Writer) !void {
        try writer.print("{d}.{d}.{d}.{d}", .{
            (self.addr >> 24) & 0xff,
            (self.addr >> 16) & 0xff,
            (self.addr >> 8) & 0xff,
            self.addr & 0xff,
        });
    }
};

pub const IpHdr = struct {
    const Self = @This();

    pub const hdr_len_min = 20;
    const hdr_len_max = 60;

    const Vhl = packed struct(u8) {
        hlen_4byte: u4,
        version: u4,
    };

    const FlagsOffset = packed struct(u16) {
        offset: u13,
        flags: IpHdrFlags,
    };

    version: u4,
    hlen_4byte: u4,
    tos: u8,
    total: u16,
    id: u16,
    flags: IpHdrFlags,
    offset: u13,
    ttl: u8,
    protocol: IpProtocolType,
    sum: u16 = 0,
    src: IpAddr,
    dst: IpAddr,

    pub fn hlen(self: Self) u16 {
        return @as(u16, self.hlen_4byte) << 2;
    }

    pub const Decoded = struct {
        hdr: Self,
        payload: []const u8,
        raw: []const u8,
    };

    pub fn decode(packet: []const u8) !Decoded {
        var r: std.Io.Reader = .fixed(packet);
        const vhl: Vhl = @bitCast(try r.takeByte());
        const tos = try r.takeByte();
        const total = try r.takeInt(u16, .big);
        const id = try r.takeInt(u16, .big);
        const flags_offset: FlagsOffset = @bitCast(try r.takeInt(u16, .big));
        const ttl = try r.takeByte();
        const protocol_int = try r.takeByte();
        const sum = try r.takeInt(u16, .big);
        const src: IpAddr = .fromBytes(try r.takeArray(IpAddr.len));
        const dst: IpAddr = .fromBytes(try r.takeArray(IpAddr.len));
        const self = Self{
            .version = vhl.version,
            .hlen_4byte = vhl.hlen_4byte,
            .tos = tos,
            .total = total,
            .id = id,
            .flags = flags_offset.flags,
            .offset = flags_offset.offset,
            .ttl = ttl,
            .protocol = std.enums.fromInt(IpProtocolType, protocol_int) orelse {
                util.errorf(@src(), "unknown protocol: {d}", .{protocol_int});
                return error.IpUnknownProtocol;
            },
            .sum = sum,
            .src = src,
            .dst = dst,
        };
        try self.validate(packet);
        return .{
            .hdr = self,
            .payload = packet[self.hlen()..self.total],
            .raw = packet,
        };
    }

    fn validate(self: Self, packet: []const u8) !void {
        if (self.version != version_v4) {
            util.errorf(@src(), "ip version error, v={d}", .{self.version});
            return error.IpVersionError;
        }
        if (packet.len < self.total) {
            util.errorf(@src(), "total length error: len={d} < total={d}", .{ packet.len, self.total });
            return error.IpTotalLengthError;
        }
        if (packet.len < self.hlen()) {
            util.errorf(@src(), "header length error: len={d} < hlen={d}", .{ packet.len, self.hlen() });
            return error.IpHeaderLengthError;
        }
        if (self.total < self.hlen()) {
            util.errorf(@src(), "total length error: total={d} < hlen={d}", .{ self.total, self.hlen() });
            return error.IpTotalLengthError;
        }
        if (util.cksum16(packet[0..self.hlen()], 0) != 0) {
            util.errorf(@src(), "checksum error", .{});
            return error.IpChecksumError;
        }
    }

    pub fn encode(self: Self, w: *std.Io.Writer) !void {
        std.debug.assert(self.hlen() == hdr_len_min);
        const start = w.buffered().len;
        try w.writeByte(@bitCast(Vhl{ .hlen_4byte = self.hlen_4byte, .version = self.version }));
        try w.writeByte(self.tos);
        try w.writeInt(u16, self.total, .big);
        try w.writeInt(u16, self.id, .big);
        try w.writeInt(u16, @bitCast(FlagsOffset{ .offset = self.offset, .flags = self.flags }), .big);
        try w.writeByte(self.ttl);
        try w.writeByte(@intFromEnum(self.protocol));
        try w.writeInt(u16, 0, .big);
        try w.writeAll(&self.src.toBytes());
        try w.writeAll(&self.dst.toBytes());
        const hdr_bytes = w.buffered()[start..];
        std.mem.writeInt(u16, hdr_bytes[10..12], util.cksum16(hdr_bytes, 0), .big);
    }

    pub fn format(self: Self, writer: *std.Io.Writer) !void {
        try writer.print("        vhl: [v={d}, hl={d} ({d})]\n", .{ self.version, self.hlen_4byte, self.hlen() });
        try writer.print("        tos: 0x{x:0>2}\n", .{self.tos});
        try writer.print("      total: {d} (payload={d})\n", .{ self.total, self.total - self.hlen() });
        try writer.print("         id: {d}\n", .{self.id});
        try writer.print("     offset: [flags={f}, offset={d}]\n", .{ self.flags, self.offset });
        try writer.print("        ttl: {d}\n", .{self.ttl});
        try writer.print("   protocol: {t}\n", .{self.protocol});
        try writer.print("        sum: 0x{x:0>4}\n", .{self.sum});
        try writer.print("        src: {f}\n", .{self.src});
        try writer.print("        dst: {f}\n", .{self.dst});
    }
};

pub const IpIface = struct {
    const Self = @This();
    pub const family: device.IfaceFamily = .ip;

    iface: device.Iface,
    unicast: IpAddr,
    netmask: IpAddr,
    broadcast: IpAddr,

    pub fn create(unicast: IpAddr, netmask: IpAddr) !*Self {
        const allocator = platform.allocator();
        const self = try allocator.create(Self);

        const broadcast = IpAddr{ .addr = (unicast.addr & netmask.addr) | ~netmask.addr };
        self.* = .{
            .iface = .{
                .family = family,
            },
            .unicast = unicast,
            .netmask = netmask,
            .broadcast = broadcast,
        };

        return self;
    }

    pub fn dev(self: *Self) *device.Device {
        return self.iface.dev;
    }
};

pub const IpProtocolType = enum(u8) {
    icmp = 1,
    tcp = 6,
    udp = 17,
};

const IpProtocolHandler = *const fn (
    hdr: *const IpHdr.Decoded,
    data: []const u8,
    iface: *IpIface,
) anyerror!void;

const IpProtocol = struct { type: IpProtocolType, handler: IpProtocolHandler };

var ifaces: std.ArrayList(*IpIface) = .empty;
var protocols: std.ArrayList(IpProtocol) = .empty;

pub fn init() !void {
    net.register(.ip, input) catch |err| {
        util.errorf(@src(), "net.register() failure: {t}", .{err});
        return err;
    };
}

pub fn registerIface(dev: *device.Device, iface: *IpIface) !void {
    const allocator = platform.allocator();
    try dev.addIface(&iface.iface);

    const network = iface.unicast.masked(iface.netmask);
    route.add(network, iface.netmask, IpAddr.any, iface) catch |err| {
        util.errorf(@src(), "route.add() failure: {t}", .{err});
        return err;
    };

    try ifaces.append(allocator, iface);
}

pub fn registerProtocol(typ: IpProtocolType, handler: IpProtocolHandler) !void {
    for (protocols.items) |proto| {
        if (proto.type == typ) {
            util.errorf(@src(), "already registered, type={t}", .{typ});
            return error.IpProtocolAlreadyRegistered;
        }
    }

    const allocator = platform.allocator();
    try protocols.append(allocator, .{
        .type = typ,
        .handler = handler,
    });

    util.infof(@src(), "success, type={t}", .{typ});
}

fn input(data: []const u8, dev: *device.Device) !void {
    util.debugf(@src(), "dev={s}, len={d}", .{ dev.name(), data.len });
    util.debugdump(data);
    const d = try IpHdr.decode(data);
    const hdr = d.hdr;
    if (hdr.flags.mf or hdr.offset != 0) {
        util.errorf(@src(), "fragments does not supported", .{});
        return error.IpFragmentedPacketNotSupported;
    }
    const iface = dev.getIface(IpIface) orelse return;
    const dst = hdr.dst;
    if (!dst.eql(iface.unicast)) {
        if (!dst.eql(iface.broadcast) and !dst.eql(IpAddr.broadcast)) {
            // ignore: for other host
            return;
        }
    }
    util.debugf(@src(), "permit, dev={s}, iface={f}", .{ dev.name(), iface.unicast });
    util.dumpf("{f}", .{hdr});
    for (protocols.items) |proto| {
        if (proto.type == hdr.protocol) {
            try proto.handler(&d, d.payload, iface);
            return;
        }
    }
    // unsupported protocol
    if (hdr.hlen() + 8 <= hdr.total) {
        // It should not be sent in response to ICMP error messages, but ICMP is always registered and will not reach this point.
        _ = try icmp.output(.{ .dest_unreachable = .{ .code = .protocol_unreachable } }, data[0 .. hdr.hlen() + 8], iface.unicast, hdr.src);
    }
}

pub fn output(protocol: IpProtocolType, data: []const u8, src: IpAddr, dst: IpAddr) !usize {
    util.debugf(@src(), "{f} => {f}, protocol={d}, len={d}", .{ src, dst, protocol, data.len });
    if (src.eql(IpAddr.any) and dst.eql(IpAddr.broadcast)) {
        util.errorf(@src(), "source address is required for broadcast addresses", .{});
        return error.IpRoutingNotImplemented;
    }
    const r = route.lookup(dst) orelse {
        util.errorf(@src(), "no route to host, dst={f}", .{dst});
        return error.IpRouteNotFound;
    };
    const iface = r.iface;
    if (!src.eql(IpAddr.any) and !src.eql(iface.unicast)) {
        util.errorf(@src(), "unable to output with specified source address, src={f}", .{src});
        return error.IpSourceAddressNotAvailable;
    }
    if (iface.dev().mtu < IpHdr.hdr_len_min + data.len) {
        util.errorf(@src(), "too long, dev={s}, mtu={d} < len={d}", .{ iface.dev().name(), iface.dev().mtu, IpHdr.hdr_len_min + data.len });
        return error.IpPayloadTooLarge;
    }

    const id = platform.random16();
    var buf: [total_size_max]u8 = undefined;
    const packet = buildPacket(&buf, protocol, data, id, 0, iface.unicast, dst) catch |err| {
        util.errorf(@src(), "buildPacket() failure: {t}", .{err});
        return err;
    };
    const next = if (!r.nexthop.eql(IpAddr.any)) r.nexthop else dst;
    outputDevice(iface, packet, next) catch |err| {
        util.errorf(@src(), "outputDevice() failure: {t}", .{err});
        return err;
    };
    return packet.len;
}

fn selectIface(addr: IpAddr) ?*IpIface {
    for (ifaces.items) |entry| {
        if (entry.unicast.eql(addr)) {
            return entry;
        }
    }
    return null;
}

fn outputDevice(iface: *IpIface, data: []const u8, target: IpAddr) !void {
    util.debugf(@src(), "dev={s}, len={d}, target={f}", .{ iface.dev().name(), data.len, target });
    var hwaddr: [device.Device.addr_len]u8 = undefined;
    if (iface.dev().flags.need_arp) {
        if (target.eql(iface.broadcast) or target.eql(IpAddr.broadcast)) {
            hwaddr = iface.dev().broadcast;
        } else {
            const ha = arp.resolve(iface, target) catch |err| switch (err) {
                error.ArpResolveWaiting => return,
                else => return err,
            };
            const ha_bytes = ha.toBytes();
            hwaddr[0..ha_bytes.len].* = ha_bytes;
        }
    }
    return iface.dev().output(.ip, data, &hwaddr);
}

fn buildPacket(buf: []u8, protocol: IpProtocolType, data: []const u8, id: u16, offset: u13, src: IpAddr, dst: IpAddr) ![]const u8 {
    const hlen = IpHdr.hdr_len_min;
    const hdr = IpHdr{
        .version = version_v4,
        .hlen_4byte = hlen >> 2,
        .tos = 0,
        .total = @intCast(hlen + data.len),
        .id = id,
        .flags = .{},
        .offset = offset,
        .ttl = 0xff,
        .protocol = protocol,
        .src = src,
        .dst = dst,
    };
    var w: std.Io.Writer = .fixed(buf);
    try hdr.encode(&w);
    try w.writeAll(data);
    const packet = w.buffered();
    const d = try IpHdr.decode(packet);
    util.dumpf("{f}", .{d.hdr});
    return packet;
}

pub const route = struct {
    const IpRoute = struct {
        network: IpAddr,
        netmask: IpAddr,
        nexthop: IpAddr,
        iface: *IpIface,
    };

    var routes: std.ArrayList(IpRoute) = .empty;

    // NOTE: must not be called after run()
    pub fn setDefaultGateway(iface: *IpIface, gateway: IpAddr) !void {
        add(IpAddr.any, IpAddr.any, gateway, iface) catch |err| {
            util.errorf(@src(), "routeSetDefaultGateway() failure: {t}", .{err});
            return err;
        };
    }

    pub fn getIface(dst: IpAddr) ?*IpIface {
        const r = lookup(dst) orelse return null;
        return r.iface;
    }

    // NOTE: must not be called after run()
    fn add(network: IpAddr, netmask: IpAddr, nexthop: IpAddr, iface: *IpIface) !void {
        if (!nexthop.eql(IpAddr.any)) {
            util.infof(@src(), "{f}/{f} via {f} dev {s} src {f}", .{
                network,
                netmask,
                nexthop,
                iface.dev().name(),
                iface.unicast,
            });
        } else {
            util.infof(@src(), "{f}/{f} dev {s} src {f}", .{
                network,
                netmask,
                iface.dev().name(),
                iface.unicast,
            });
        }

        const allocator = platform.allocator();
        try routes.append(allocator, .{
            .network = network,
            .netmask = netmask,
            .nexthop = nexthop,
            .iface = iface,
        });
    }

    fn lookup(dst: IpAddr) ?*IpRoute {
        var candidate: ?*IpRoute = null;
        for (routes.items) |*r| {
            if (!dst.isInSubnet(r.network, r.netmask)) {
                continue;
            }
            if (candidate == null or candidate.?.netmask.isLessSpecificThan(r.netmask)) {
                candidate = r;
            }
        }
        return candidate;
    }
};

test "IpHdr round-trip" {
    const packet = [_]u8{
        0x45, 0x00, 0x00, 0x30,
        0x00, 0x80, 0x00, 0x00,
        0xff, 0x01, 0xbd, 0x4a,
        0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01,
        0x08, 0x00, 0x35, 0x64,
        0x00, 0x80, 0x00, 0x01,
        0x31, 0x32, 0x33, 0x34,
        0x35, 0x36, 0x37, 0x38,
        0x39, 0x30, 0x21, 0x40,
        0x23, 0x24, 0x25, 0x5e,
        0x26, 0x2a, 0x28, 0x29,
    };
    const d = try IpHdr.decode(&packet);
    var buf: [IpHdr.hdr_len_min]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try d.hdr.encode(&w);
    try std.testing.expectEqualSlices(u8, packet[0..IpHdr.hdr_len_min], w.buffered());
}
