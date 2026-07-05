const std = @import("std");
const build_options = @import("build_options");

const device = @import("device.zig");
const net = @import("net.zig");
const platform = @import("platform/linux/platform.zig");
const util = @import("util.zig");

const IP_VERSION_V4 = 4;

const IP_HDR_SIZE_MIN = 20;
const IP_HDR_SIZE_MAX = 60;

const IP_TOTAL_SIZE_MAX = std.math.maxInt(u16);
const IP_PAYLOAD_SIZE_MAX = IP_TOTAL_SIZE_MAX - IP_HDR_SIZE_MIN;

const IpHdrFlags = packed struct(u3) {
    mf: bool,
    df: bool,
    rf: bool,

    pub fn format(
        self: @This(),
        writer: *std.Io.Writer,
    ) !void {
        try writer.print("{x}", .{@as(u3, @bitCast(self))});
    }
};

pub const IpAddr = struct {
    const Self = @This();

    pub const LEN = 4;

    addr: u32,

    pub const any = IpAddr{ .addr = 0x00000000 };
    pub const broadcast = IpAddr{ .addr = 0xffffffff };

    pub fn fromBytes(bytes: [LEN]u8) IpAddr {
        return IpAddr{ .addr = std.mem.readInt(u32, bytes[0..], .big) };
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

    pub fn format(self: Self, writer: anytype) !void {
        try writer.print("{d}.{d}.{d}.{d}", .{
            (self.addr >> 24) & 0xff,
            (self.addr >> 16) & 0xff,
            (self.addr >> 8) & 0xff,
            self.addr & 0xff,
        });
    }
};

const IpHdrView = struct {
    const Self = @This();

    const OFFSET_MASK = 0x1fff;

    packet: []const u8,

    pub fn parse(packet: []const u8) !Self {
        if (packet.len < IP_HDR_SIZE_MIN) {
            util.errorf(@src(), "too short, len={d}", .{packet.len});
            return error.IpPacketTooShort;
        }
        const self = Self{ .packet = packet };
        if (self.v() != IP_VERSION_V4) {
            util.errorf(@src(), "ip version error, v={d}", .{self.v()});
            return error.IpVersionError;
        }
        if (packet.len < self.hlen()) {
            util.errorf(@src(), "header length error: len={d}  hlen={d}", .{ packet.len, self.hlen() });
            return error.IpHeaderLengthError;
        }
        if (util.cksum16(packet, 0) != 0) {
            util.errorf(@src(), "checksum error", .{});
            return error.IpChecksumError;
        }
        if (packet.len < self.total()) {
            util.errorf(@src(), "total length error: len={d} < total={d}", .{ packet.len, self.total() });
            return error.IpTotalLengthError;
        }
        return self;
    }

    pub fn vhl(self: Self) u8 {
        return self.packet[0];
    }

    pub fn v(self: Self) u4 {
        return @intCast(self.vhl() >> 4);
    }

    pub fn hlen(self: Self) u8 {
        const hl: u8 = @intCast(self.vhl() & 0x0f);
        return hl << 2;
    }

    pub fn tos(self: Self) u8 {
        return self.packet[1];
    }

    pub fn total(self: Self) u16 {
        return std.mem.readInt(u16, self.packet[2..4], .big);
    }

    pub fn id(self: Self) u16 {
        return util.ntoh16(std.mem.readInt(u16, self.packet[4..6], .big));
    }

    pub fn offsetFlag(self: Self) u16 {
        return std.mem.readInt(u16, self.packet[6..8], .big);
    }

    pub fn flags(self: Self) IpHdrFlags {
        return @bitCast(@as(u3, @truncate(self.offsetFlag() >> 13)));
    }

    pub fn offset(self: Self) u16 {
        return self.offsetFlag() & OFFSET_MASK;
    }

    pub fn ttl(self: Self) u8 {
        return self.packet[8];
    }

    pub fn protocol(self: Self) u8 {
        return self.packet[9];
    }

    pub fn sum(self: Self) u16 {
        return util.ntoh16(std.mem.readInt(u16, self.packet[10..12], .big));
    }

    pub fn src(self: Self) IpAddr {
        return IpAddr.fromBytes(@as([4]u8, self.packet[12..16].*));
    }

    pub fn dst(self: Self) IpAddr {
        return IpAddr.fromBytes(@as([4]u8, self.packet[16..20].*));
    }

    pub fn format(self: Self, writer: anytype) !void {
        try writer.print("        vhl: 0x{x:0>2} [v={d}, hl={d} ({d})]\n", .{ self.vhl(), self.v(), self.hlen() >> 2, self.hlen() });
        try writer.print("        tos: 0x{x:0>2}\n", .{self.tos()});
        try writer.print("      total: {d} (payload={d})\n", .{ self.total(), self.total() - self.hlen() });
        try writer.print("         id: {d}\n", .{self.id()});
        try writer.print("     offset: 0x{x:0>4} [flags={f}, offset={d}]\n", .{ self.offsetFlag(), self.flags(), self.offset() });
        try writer.print("        ttl: {d}\n", .{self.ttl()});
        try writer.print("   protocol: {d}\n", .{self.protocol()});
        try writer.print("        sum: 0x{x:0>4}\n", .{self.sum()});
        try writer.print("        src: {f}\n", .{self.src()});
        try writer.print("        dst: {f}\n", .{self.dst()});
        if (build_options.hexdump) {
            util.hexdump(std.debug, self.packet);
        }
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
};

var ifaces: std.ArrayList(*IpIface) = .empty;

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

pub fn selectIface(addr: IpAddr) ?*IpIface {
    for (ifaces.items) |entry| {
        if (entry.unicast.eql(addr)) {
            return entry;
        }
    }
    return null;
}

fn input(data: []const u8, dev: *device.Device) !void {
    util.debugf(@src(), "dev={s}, len={d}", .{ dev.name(), data.len });
    util.debugdump(data);
    const hdr = try IpHdrView.parse(data);
    if (hdr.flags().mf or hdr.offset() != 0) {
        util.errorf(@src(), "fragments does not supported", .{});
        return error.IpFragmentedPacketNotSupported;
    }
    const iface = dev.getIface(IpIface) orelse return;
    const dst = hdr.dst();
    if (!dst.eql(iface.unicast)) {
        if (!dst.eql(iface.broadcast) and !dst.eql(IpAddr.broadcast)) {
            // ignore: for other host
            return;
        }
    }
    util.debugf(@src(), "permit, dev={s}, iface={f}", .{ dev.name(), iface.unicast });
    std.debug.print("{f}", .{hdr});
}
