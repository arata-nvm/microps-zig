const std = @import("std");
const linux = std.os.linux;

const microps = @import("microps");
const ether = microps.ether;
const util = microps.util;

const CLONE_DEVICE = "/dev/net/tun";

const IFF_TAP: u16 = 0x0002;
const IFF_NO_PI: u16 = 0x1000;
const TUNSETIFF: u32 = 0x400454ca;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    if (args.len != 2) {
        util.errorf(@src(), "usage: {s} <ifname>", .{args[0]});
        return;
    }

    const ifname = args[1];
    if (linux.IFNAMESIZE <= ifname.len) {
        util.errorf(@src(), "ifname too long: {s}", .{ifname});
        return;
    }

    const fd = std.posix.openat(std.posix.AT.FDCWD, CLONE_DEVICE, .{ .ACCMODE = .RDWR }, 0) catch |err| {
        util.errorf(@src(), "open: {t}", .{err});
        return err;
    };
    defer _ = linux.close(fd);

    var ifr = std.mem.zeroes(linux.ifreq);
    @memcpy(ifr.ifrn.name[0..ifname.len], ifname);
    ifr.ifru.flags = @bitCast(IFF_TAP | IFF_NO_PI);

    switch (std.posix.errno(linux.ioctl(fd, TUNSETIFF, @intFromPtr(&ifr)))) {
        .SUCCESS => {},
        else => |e| {
            util.errorf(@src(), "ioctl: {t}", .{e});
            return;
        },
    }

    util.infof(@src(), "waiting for packets from <{s}>...", .{ifname});

    var buf: [2048]u8 = undefined;
    while (true) {
        const n = std.posix.read(fd, &buf) catch |err| {
            util.errorf(@src(), "recv: {t}", .{err});
            return err;
        };
        util.infof(@src(), "receive {d} bytes data", .{n});
        const hdr = ether.EtherHdr.decode(buf[0..n]) catch {
            continue;
        };
        std.debug.print("{f}", .{hdr});
        util.debugdump(buf[0..n]);
    }
}
