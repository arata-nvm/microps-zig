const std = @import("std");
const linux = std.os.linux;

const device = @import("../../../device.zig");
const ether = @import("../../../ether.zig");
const intr = @import("../intr.zig");
const net = @import("../../../net.zig");
const platform = @import("../platform.zig");
const util = @import("../../../util.zig");

const clone_device = "/dev/net/tun";

pub const TUNSETIFF: u32 = linux.IOCTL.IOW('T', 202, i32);
pub const IFF_TAP: u16 = 0x0002;
pub const IFF_NO_PI: u16 = 0x1000;

const EtherTap = struct {
    const Self = @This();

    dev: device.Device,
    ifname_buf: [device.Device.ifname_size - 1:0]u8,
    fd: i32,
    irq: u32,

    fn from(dev: *device.Device) *Self {
        return @fieldParentPtr("dev", dev);
    }

    fn ifname(self: *const Self) [:0]const u8 {
        return std.mem.sliceTo(&self.ifname_buf, 0);
    }

    fn ifr(self: *Self) linux.ifreq {
        var i = std.mem.zeroes(linux.ifreq);
        @memcpy(i.ifrn.name[0..self.ifname().len], self.ifname());
        return i;
    }
};

fn sys(rc: usize) !usize {
    switch (linux.errno(rc)) {
        .SUCCESS => return rc,
        else => |err| return std.posix.unexpectedErrno(err),
    }
}

pub fn init(name: []const u8, addr: ?ether.EtherAddr) !*device.Device {
    if (addr) |a| {
        util.infof(@src(), "name={s}, addr={f}", .{ name, a });
    } else {
        util.infof(@src(), "name={s}, addr=(none)", .{name});
    }

    if (device.Device.ifname_size <= name.len) {
        return error.EtherTapNameTooLong;
    }

    const allocator = platform.allocator;
    const tap = try allocator.create(EtherTap);
    errdefer allocator.destroy(tap);

    tap.* = .{
        .dev = device.Device.init(
            .ethernet,
            ether.payload_size_max,
            .{ .broadcast = true, .need_arp = true },
            ether.EtherHdr.hdr_len,
            ether.EtherAddr.len,
            ops,
        ),
        .ifname_buf = @splat(0),
        .fd = -1,
        .irq = intr.irqBase(),
    };
    @memcpy(tap.ifname_buf[0..name.len], name);

    if (addr) |a| {
        tap.dev.addr[0..ether.EtherAddr.len].* = a.toBytes();
    }
    tap.dev.broadcast[0..ether.EtherAddr.len].* = ether.EtherAddr.broadcast.toBytes();

    device.register(&tap.dev) catch |err| {
        util.errorf(@src(), "device.register() failure: {t}", .{err});
        return err;
    };
    intr.registerTyped(device.Device, tap.irq, isr, .{ .shared = true }, &tap.dev) catch |err| {
        util.errorf(@src(), "intr.register() failure: {t}", .{err});
        return err;
    };

    util.infof(@src(), "success, dev={s}\n", .{tap.dev.name()});
    return &tap.dev;
}

pub fn setDefaultAddr(dev: *device.Device) !void {
    const soc: i32 = @intCast(sys(linux.socket(std.c.AF.INET, std.c.SOCK.DGRAM, 0)) catch |err| {
        util.errorf(@src(), "socket: {t}, dev={s}", .{ err, dev.name() });
        return err;
    });
    defer _ = linux.close(soc);

    const tap = EtherTap.from(dev);
    var ifr = tap.ifr();
    _ = sys(linux.ioctl(soc, linux.SIOCGIFHWADDR, @intFromPtr(&ifr))) catch |err| {
        util.errorf(@src(), "ioctl(SIOCGIFHWADDR): {t}, dev={s}", .{ err, dev.name() });
    };
    dev.addr[0..ether.EtherAddr.len].* = ifr.ifru.hwaddr.data[0..ether.EtherAddr.len].*;
}

const ops = device.DeviceOps{
    .openFn = open,
    .closeFn = close,
    .outputFn = output,
};

fn open(dev: *device.Device) !void {
    const tap = EtherTap.from(dev);
    tap.fd = @intCast(sys(linux.open(clone_device, .{ .ACCMODE = .RDWR }, 0)) catch |err| {
        util.errorf(@src(), "open: {t}, dev={s}", .{ err, dev.name() });
        return err;
    });

    var ifr = tap.ifr();
    ifr.ifru.flags = @bitCast(IFF_TAP | IFF_NO_PI);
    _ = sys(linux.ioctl(tap.fd, TUNSETIFF, @intFromPtr(&ifr))) catch |err| {
        util.errorf(@src(), "ioctl(TUNSETIFF): {t}, dev={s}", .{ err, dev.name() });
        return err;
    };
    const pid: usize = @intCast(linux.getpid());
    _ = sys(linux.fcntl(tap.fd, std.c.F.SETOWN, pid)) catch |err| {
        util.errorf(@src(), "fcntl(F_SETOWN): {t}, dev={s}", .{ err, dev.name() });
        return err;
    };
    const val = sys(linux.fcntl(tap.fd, std.c.F.GETFL, 0)) catch |err| {
        util.errorf(@src(), "fcntl(F_GETFL): {t}, dev={s}", .{ err, dev.name() });
        return err;
    };
    const o: linux.O = .{ .ASYNC = true, .NONBLOCK = true };
    _ = sys(linux.fcntl(tap.fd, std.c.F.SETFL, val | @as(u32, @bitCast(o)))) catch |err| {
        util.errorf(@src(), "fcntl(F_SETFL): {t}, dev={s}", .{ err, dev.name() });
        return err;
    };
    _ = sys(linux.fcntl(tap.fd, std.c.F.SETSIG, tap.irq)) catch |err| {
        util.errorf(@src(), "fcntl(F_SETSIG): {t}, dev={s}", .{ err, dev.name() });
        return err;
    };

    var addr = ether.EtherAddr.fromBytes(dev.addr[0..ether.EtherAddr.len]);
    if (addr.eql(ether.EtherAddr.any)) {
        setDefaultAddr(dev) catch |err| {
            util.errorf(@src(), "setDefaultAddr() failure: {t}, dev={s}", .{ err, dev.name() });
            return err;
        };
        addr = ether.EtherAddr.fromBytes(dev.addr[0..ether.EtherAddr.len]);
    }

    const ts = linux.timespec{ .sec = 0, .nsec = 100 * std.time.ns_per_ms };
    _ = linux.nanosleep(&ts, null);

    util.infof(@src(), "dev={s}, addr={f}", .{ dev.name(), addr });
}

fn close(dev: *device.Device) !void {
    util.infof(@src(), "dev={s}", .{dev.name()});
    const tap = EtherTap.from(dev);
    _ = sys(linux.close(tap.fd)) catch |err| {
        util.errorf(@src(), "close: {t}, dev={s}", .{ err, dev.name() });
        return err;
    };
}

fn output(dev: *device.Device, typ: net.ProtocolType, data: []const u8, dst: ?[]const u8) !void {
    const dst_addr = dst orelse {
        util.errorf(@src(), "no destination address, dev={s}", .{dev.name()});
        return error.EtherTapNoDestinationAddress;
    };
    if (dst_addr.len < ether.EtherAddr.len) {
        return error.EtherTapDestinationTooShort;
    }

    const hdr = ether.EtherHdr{
        .src = ether.EtherAddr.fromBytes(dev.addr[0..ether.EtherAddr.len]),
        .dst = ether.EtherAddr.fromBytes(dst_addr[0..ether.EtherAddr.len]),
        .type = typ,
    };

    var frame: [ether.frame_max]u8 = undefined;
    var w: std.Io.Writer = .fixed(&frame);
    try hdr.encode(&w);
    try w.writeAll(data);

    const frame_len = @max(w.buffered().len, ether.frame_min);
    util.debugf(@src(), "dev={s}, type=0x{x:0>4}, len={d}", .{ dev.name(), typ, frame_len });
    util.dumpf("{f}", .{hdr});

    const tap = EtherTap.from(dev);
    _ = sys(linux.write(tap.fd, &frame, frame_len)) catch |err| {
        util.errorf(@src(), "write: {t}", .{err});
        return err;
    };
}

fn input(dev: *device.Device, frame: []const u8) !void {
    const d = ether.EtherHdr.decode(frame) catch |err| {
        util.errorf(@src(), "decode: {t}", .{err});
        return err;
    };

    const dst = d.hdr.dst;
    const addr = ether.EtherAddr.fromBytes(dev.addr[0..ether.EtherAddr.len]);
    if (!dst.eql(addr)) {
        if (!dst.eql(.broadcast)) {
            // for other host
            return;
        }
    }

    util.debugf(@src(), "dev={s}, type=0x{x:0>4}, len={d}", .{ dev.name(), d.hdr.type, frame.len });
    util.dumpf("{f}", .{d.hdr});
    return net.input(d.hdr.type, d.payload, dev);
}

fn isr(_: u32, dev: *device.Device) !void {
    const tap = EtherTap.from(dev);

    var buf: [ether.frame_max]u8 = undefined;
    while (true) {
        const n = std.posix.read(tap.fd, &buf) catch |err| switch (err) {
            error.WouldBlock => return,
            else => {
                util.errorf(@src(), "read: {t}, dev={s}", .{ err, dev.name() });
                return err;
            },
        };
        try input(dev, buf[0..n]);
    }
}
