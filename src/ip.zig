const std = @import("std");

const arp = @import("arp.zig");
const device = @import("device.zig");
const icmp = @import("icmp.zig");
const net = @import("net.zig");
const platform = @import("platform/linux/platform.zig");
const util = @import("util.zig");

const version_v4 = 4;

const total_size_max = std.math.maxInt(u16);
pub const payload_size_max = total_size_max - IpHdr.size_min;

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

    pub fn fromBytes(bytes: [len]u8) IpAddr {
        return IpAddr{ .addr = std.mem.readInt(u32, bytes[0..], .big) };
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
        return fromBytes(parts);
    }

    pub fn eql(self: Self, other: Self) bool {
        return self.addr == other.addr;
    }

    pub fn isSameSubnet(self: Self, other: Self, netmask: Self) bool {
        return (self.addr & netmask.addr) == (other.addr & netmask.addr);
    }

    pub fn format(self: Self, writer: anytype) !void {
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

    pub const size_min = 20;
    const size_max = 60;
    const offset_mask = 0x1fff;

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

    fn hlen(self: Self) u16 {
        return @as(u16, self.hlen_4byte) << 2;
    }

    pub fn decode(packet: []const u8) !Self {
        if (packet.len < size_min) {
            util.errorf(@src(), "too short, len={d}", .{packet.len});
            return error.IpPacketTooShort;
        }
        const protocol = std.enums.fromInt(IpProtocolType, packet[9]) orelse {
            util.errorf(@src(), "unknown protocol: {d}", .{packet[9]});
            return error.IpUnknownProtocol;
        };
        const self = Self{
            .version = @intCast(packet[0] >> 4),
            .hlen_4byte = @intCast(packet[0] & 0x0f),
            .tos = packet[1],
            .total = std.mem.readInt(u16, packet[2..4], .big),
            .id = std.mem.readInt(u16, packet[4..6], .big),
            .flags = @bitCast(@as(u3, @truncate(std.mem.readInt(u16, packet[6..8], .big) >> 13))),
            .offset = @intCast(std.mem.readInt(u16, packet[6..8], .big) & offset_mask),
            .ttl = packet[8],
            .protocol = protocol,
            .sum = std.mem.readInt(u16, packet[10..12], .big),
            .src = IpAddr.fromBytes(packet[12..16].*),
            .dst = IpAddr.fromBytes(packet[16..20].*),
        };
        try self.validate(packet);
        return self;
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

    pub fn encode(self: *Self, buf: []u8) !void {
        if (buf.len < self.hlen()) {
            util.errorf(@src(), "buffer too short: len={d} < hlen={d}", .{ buf.len, self.hlen() });
            return error.IpBufferTooShort;
        }

        buf[0] = (@as(u8, self.version) << 4) | self.hlen_4byte;
        buf[1] = self.tos;
        std.mem.writeInt(u16, buf[2..4], self.total, .big);
        std.mem.writeInt(u16, buf[4..6], self.id, .big);
        std.mem.writeInt(u16, buf[6..8], (@as(u16, @as(u3, @bitCast(self.flags))) << 13) | self.offset, .big);
        buf[8] = self.ttl;
        buf[9] = @intFromEnum(self.protocol);
        std.mem.writeInt(u16, buf[10..12], 0, .big);
        std.mem.writeInt(u32, buf[12..16], self.src.addr, .big);
        std.mem.writeInt(u32, buf[16..20], self.dst.addr, .big);
        std.debug.assert(self.hlen() == size_min);
        self.sum = util.cksum16(buf[0..self.hlen()], 0);
        std.mem.writeInt(u16, buf[10..12], self.sum, .big);
    }

    pub fn format(self: Self, writer: anytype) !void {
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

    pub fn create(allocator: std.mem.Allocator, unicast: IpAddr, netmask: IpAddr) !*Self {
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

const IpProtocolType = enum(u8) {
    icmp = 1,
    tcp = 6,
    udp = 17,
};

const IpProtocolHandler = *const fn (hdr: *const IpHdr, data: []const u8, iface: *IpIface) anyerror!void;

const IpProtocol = struct { type: IpProtocolType, handler: IpProtocolHandler };

var ifaces: std.ArrayList(*IpIface) = .empty;
var protocols: std.ArrayList(*IpProtocol) = .empty;

pub fn init() !void {
    net.register(.ip, input) catch |err| {
        util.errorf(@src(), "net.register() failure: {t}", .{err});
        return err;
    };
}

pub fn registerIface(dev: *device.Device, iface: *IpIface) !void {
    const allocator = platform.allocator;
    try dev.addIface(&iface.iface);
    try ifaces.append(allocator, iface);
}

pub fn registerProtocol(typ: IpProtocolType, handler: IpProtocolHandler) !void {
    for (protocols.items) |proto| {
        if (proto.type == typ) {
            util.errorf(@src(), "already registered, type={t}", .{typ});
            return error.IpProtocolAlreadyRegistered;
        }
    }

    const allocator = platform.allocator;
    const proto = try allocator.create(IpProtocol);
    errdefer allocator.destroy(proto);

    proto.type = typ;
    proto.handler = handler;
    try protocols.append(allocator, proto);

    util.infof(@src(), "success, type={t}", .{typ});
}

fn input(data: []const u8, dev: *device.Device) !void {
    util.debugf(@src(), "dev={s}, len={d}", .{ dev.name(), data.len });
    util.debugdump(data);
    const hdr = try IpHdr.decode(data);
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
    std.debug.print("{f}", .{hdr});
    for (protocols.items) |proto| {
        if (proto.type == @as(IpProtocolType, hdr.protocol)) {
            try proto.handler(&hdr, data[hdr.hlen()..], iface);
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
    if (src.eql(IpAddr.any)) {
        util.errorf(@src(), "ip routing not implemented", .{});
        return error.IpRoutingNotImplemented;
    }
    const iface = selectIface(src) orelse {
        util.errorf(@src(), "iface not found: src={f}", .{src});
        return error.IpIfaceNotFound;
    };
    if (!dst.isSameSubnet(iface.unicast, iface.netmask) and !dst.eql(IpAddr.broadcast)) {
        util.errorf(@src(), "not reached, dst={f}", .{dst});
        return error.IpNotReached;
    }
    if (iface.dev().mtu < IpHdr.size_min + data.len) {
        util.errorf(@src(), "too long, dev={s}, mtu={d} < len={d}", .{ iface.dev().name(), iface.dev().mtu, IpHdr.size_min + data.len });
        return error.IpPayloadTooLarge;
    }

    const id = platform.random16();
    var buf: [total_size_max]u8 = undefined;
    const packet = buildPacket(&buf, protocol, data, id, 0, iface.unicast, dst) catch |err| {
        util.errorf(@src(), "buildPacket() failure: {t}", .{err});
        return err;
    };
    outputDevice(iface, packet, dst) catch |err| {
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
            @memcpy(hwaddr[0..iface.dev().alen], &iface.dev().broadcast);
        } else {
            const ha = arp.resolve(iface, target) catch |err| switch (err) {
                error.ArpResolveWaiting => return,
                else => return err,
            };
            @memcpy(hwaddr[0..iface.dev().alen], &ha.toBytes());
        }
    }
    return iface.dev().output(.ip, data, &hwaddr);
}

fn buildPacket(buf: []u8, protocol: IpProtocolType, data: []const u8, id: u16, offset: u13, src: IpAddr, dst: IpAddr) ![]const u8 {
    const hlen = IpHdr.size_min;
    const total = hlen + data.len;
    if (buf.len < total) {
        return error.IpBufferTooShort;
    }
    var hdr = IpHdr{
        .version = version_v4,
        .hlen_4byte = hlen >> 2,
        .tos = 0,
        .total = @intCast(total),
        .id = id,
        .flags = .{},
        .offset = offset,
        .ttl = 0xff,
        .protocol = protocol,
        .src = src,
        .dst = dst,
    };
    try hdr.encode(buf);
    @memcpy(buf[hlen..total], data);
    std.debug.print("{f}", .{hdr});
    return buf[0..total];
}

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
    var hdr = try IpHdr.decode(&packet);
    var buf: [IpHdr.size_min]u8 = undefined;
    try hdr.encode(&buf);
    try std.testing.expectEqualSlices(u8, packet[0..IpHdr.size_min], &buf);
}
