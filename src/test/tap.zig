const std = @import("std");
const linux = std.os.linux;

const microps = @import("microps");
const ether = microps.ether;
const ether_tap = microps.platform.driver.ether_tap;
const util = microps.util;

const CLONE_DEVICE = "/dev/net/tun";

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
    ifr.ifru.flags = @bitCast(ether_tap.IFF_TAP | ether_tap.IFF_NO_PI);

    switch (std.posix.errno(linux.ioctl(fd, ether_tap.TUNSETIFF, @intFromPtr(&ifr)))) {
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
        const d = ether.EtherHdr.decode(buf[0..n]) catch {
            continue;
        };
        util.dumpf("{f}", .{d.hdr});
        util.debugdump(buf[0..n]);
    }
}
