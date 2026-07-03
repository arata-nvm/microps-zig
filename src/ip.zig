const std = @import("std");
const build_options = @import("build_options");

const device = @import("device.zig");
const net = @import("net.zig");
const util = @import("util.zig");

const IP_VERSION_V4 = 4;

const IP_HDR_SIZE_MIN = 20;
const IP_HDR_SIZE_MAX = 60;

const IP_TOTAL_SIZE_MAX = std.math.maxInt(u16);
const IP_PAYLOAD_SIZE_MAX = IP_TOTAL_SIZE_MAX - IP_HDR_SIZE_MIN;

const IpHdrFlag = enum(u16) {
    MF = 0x1,
    DF = 0x2,
    RF = 0x4,
};

const IpHdrFlags = u16;

const IpAddr = struct {
    pub const Self = @This();

    pub const LEN = 4;

    addr: [LEN]u8,

    pub const any = IpAddr{ .addr = [LEN]u8{ 0x00, 0x00, 0x00, 0x00 } };
    pub const broadcast = IpAddr{ .addr = [LEN]u8{ 0xff, 0xff, 0xff, 0xff } };

    pub fn fromBytes(bytes: [LEN]u8) IpAddr {
        return IpAddr{ .addr = bytes };
    }

    pub fn format(self: Self, writer: anytype) !void {
        try writer.print("{d}.{d}.{d}.{d}", .{ self.addr[0], self.addr[1], self.addr[2], self.addr[3] });
    }
};

const IpHdrView = struct {
    pub const Self = @This();

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

    pub fn offset_flag(self: Self) u16 {
        return std.mem.readInt(u16, self.packet[6..8], .big);
    }

    pub fn flags(self: Self) IpHdrFlags {
        return self.offset_flag() >> 13;
    }

    pub fn offset(self: Self) u16 {
        return self.offset_flag() & OFFSET_MASK;
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
        try writer.print("     offset: 0x{x:0>4} [flags={x}, offset={d}]\n", .{ self.offset_flag(), self.flags(), self.offset() });
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

pub fn init() !void {
    net.register(net.ProtocolType.IP, input) catch |err| {
        util.errorf(@src(), "net.register() failure: {t}", .{err});
        return err;
    };
}

fn input(data: []const u8, dev: *device.Device) !void {
    util.debugf(@src(), "dev={s}, len={d}", .{ dev.name(), data.len });
    util.debugdump(data);
    const hdr = try IpHdrView.parse(data);
    if ((hdr.flags() & @intFromEnum(IpHdrFlag.MF)) != 0 or hdr.offset() != 0) {
        util.errorf(@src(), "fragments does not supported", .{});
        return error.IpFragmentedPacketNotSupported;
    }
    std.debug.print("{f}", .{hdr});
}
