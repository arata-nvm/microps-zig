const std = @import("std");

const device = @import("device.zig");
const ether = @import("ether.zig");
const ip = @import("ip.zig");
const net = @import("net.zig");
const util = @import("util.zig");

// Hardware Types
//  - see https://www.iana.org/assignments/arp-parameters/arp-parameters.txt
const ArpHrd = enum(u16) {
    ether = 1,
};

const ArpPro = enum(u16) {
    ip = ether.EtherType.ip,
};

const ArpOp = enum(u16) {
    request = 1,
    reply = 2,
};

const ArpHdr = struct {
    const Self = @This();

    const size = 8;

    hrd: ArpHrd,
    pro: ArpPro,
    hln: u8,
    pln: u8,
    op: ArpOp,

    pub fn decode(data: []const u8) !Self {
        if (data.len < size) {
            util.errorf(@src(), "too short, len={d}", .{data.len});
            return error.ArpHdrTooShort;
        }
        const hrd = std.mem.readInt(u16, data[0..2], .big);
        const op = std.mem.readInt(u16, data[6..8], .big);
        const self = Self{
            .hrd = std.enums.fromInt(ArpHrd, hrd) orelse {
                util.errorf(@src(), "unknown arp hrd: {d}", .{hrd});
                return error.ArpUnknownHrd;
            },
            .pro = std.mem.readInt(u16, data[2..4], .big),
            .hln = data[4],
            .pln = data[5],
            .op = std.enums.fromInt(ArpOp, op) orelse {
                util.errorf(@src(), "unknown arp op: {d}", .{op});
                return error.ArpUnknownOp;
            },
        };
        if (self.hrd != .ethernet or self.hln != ether.EtherAddr.len) {
            util.errorf(@src(), "unsupported hardware address");
            return error.ArpUnsupportedHrd;
        }
        if (self.pro != .ip or self.pln != ip.IpAddr.len) {
            util.errorf(@src(), "unsupported protocol address");
            return error.ArpUnsupportedPro;
        }
        return self;
    }

    pub fn encode(self: *Self, buf: []u8) !void {
        if (buf.len < size) {
            util.errorf(@src(), "buffer too short: len={d} < size={d}", .{ buf.len, size });
            return error.ArpBufferTooShort;
        }

        std.mem.writeInt(u16, buf[0..2], @intFromEnum(self.hrd), .big);
        std.mem.writeInt(u16, buf[2..4], @intFromEnum(self.pro), .big);
        buf[4] = self.hln;
        buf[5] = self.pln;
        std.mem.writeInt(u16, buf[6..8], @intFromEnum(self.op), .big);
    }

    pub fn format(
        self: Self,
        writer: *std.Io.Writer,
    ) !void {
        try writer.print("        hrd: 0x{x:0>4} ({t})\n", .{ @intFromEnum(self.hrd), self.hrd });
        try writer.print("        pro: 0x{x:0>4} ({t})\n", .{ @intFromEnum(self.pro), self.pro });
        try writer.print("        hln: {d}\n", .{self.hln});
        try writer.print("        pln: {d}\n", .{self.pln});
        try writer.print("         op: {d} ({t})\n", .{ @intFromEnum(self.op), self.op });
        try writer.print("        sha: {s}\n", .{self.sha});
        try writer.print("        spa: {s}\n", .{self.spa});
        try writer.print("        tha: {s}\n", .{self.tha});
        try writer.print("        tpa: {s}\n", .{self.tpa});
    }
};

const ArpEtherIp = struct {
    const Self = @This();

    const size = ArpHdr.size + ether.EtherAddr.len * 2 + ip.IpAddr.len * 2;

    hdr: ArpHdr,
    sha: ether.EtherAddr,
    spa: ip.IpAddr,
    tha: ether.EtherAddr,
    tpa: ip.IpAddr,

    pub fn decode(data: []const u8) !Self {
        if (data.len < size) {
            util.errorf(@src(), "too short, len={d}", .{data.len});
            return error.ArpPacketTooShort;
        }
        const hdr = ArpHdr.decode(data[0..ArpHdr.size]) catch |err| {
            util.errorf(@src(), "ArpHdr.decode() failure: {t}", .{err});
            return err;
        };
        const ether_len = ether.EtherAddr.len;
        const ip_len = ip.IpAddr.len;
        return Self{
            .hdr = hdr,
            .sha = ether.EtherAddr.fromBytes(data[ArpHdr.size .. ArpHdr.size + ether_len].*),
            .spa = ip.IpAddr.fromBytes(data[ArpHdr.size + ether_len .. ArpHdr.size + ether_len + ip_len].*),
            .tha = ether.EtherAddr.fromBytes(data[ArpHdr.size + ether_len + ip_len .. ArpHdr.size + ether_len * 2 + ip_len].*),
            .tpa = ip.IpAddr.fromBytes(data[ArpHdr.size + ether_len * 2 + ip_len .. ArpHdr.size + ether_len * 2 + ip_len * 2].*),
        };
    }

    pub fn encode(self: *Self, buf: []u8) !void {
        if (buf.len < size) {
            util.errorf(@src(), "buffer too short: len={d} < size={d}", .{ buf.len, size });
            return error.ArpBufferTooShort;
        }

        std.mem.writeInt(u16, buf[0..2], @intFromEnum(self.hrd), .big);
        std.mem.writeInt(u16, buf[2..4], @intFromEnum(self.pro), .big);
        buf[4] = self.hln;
        buf[5] = self.pln;
        std.mem.writeInt(u16, buf[6..8], @intFromEnum(self.op), .big);
    }
};

pub fn init() !void {
    net.register(.arp, input) catch |err| {
        util.errorf(@src(), "net.register() failure: {t}", .{err});
        return err;
    };
}

fn input(data: []const u8, dev: *device.Device) !void {
    const msg = ArpEtherIp.decode(data) catch |err| {
        util.errorf(@src(), "ArpHdr.decode() failure: {t}", .{err});
        return err;
    };
    util.debugf(@src(), "dev={s}, len={d}", .{ dev.name(), data.len });
    std.debug.print("{f}", .{msg});
    util.debugdump(data);
    const iface = dev.getIface(ip.IpIface) orelse return;
    if (iface.unicast.eql(msg.tpa)) {
        if (msg.hdr.op == .request) {
            try reply(&iface.iface, msg.sha, msg.spa, msg.sha);
        }
    }
}

fn reply(iface: *device.Iface, tha: ether.EtherAddr, tpa: ip.IpAddr, dst: ether.EtherAddr) !void {
    const msg = ArpEtherIp{
        .hdr = .{
            .hrd = .ether,
            .pro = .ip,
            .hln = ether.EtherAddr.len,
            .pln = ip.IpAddr.len,
            .op = .reply,
        },
        .sha = ether.EtherAddr.fromBytes(iface.dev.addr[0..ether.EtherAddr.len].*),
        .spa = iface.unicast,
        .tha = tha,
        .tpa = tpa,
    };
    util.debugf("dev={s}, len={d}", .{ iface.dev.name(), ArpEtherIp.size });
    std.debug.print("{f}", .{msg});

    var buf: [ArpEtherIp.size]u8 = undefined;
    try msg.encode(&buf);
    util.debugdump(buf);
    return iface.dev.output(.arp, buf, dst.toBytes());
}
