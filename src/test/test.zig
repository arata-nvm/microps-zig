const std = @import("std");
const microps = @import("microps");

const device = microps.device;
const loopback = microps.driver.loopback;
const icmp = microps.icmp;
const ip = microps.ip;
const net = microps.net;
const platform = microps.platform;
const util = microps.util;

// Scope of Internet host loopback address.
//  - see https://tools.ietf.org/html/rfc5735
pub const LOOPBACK_IP_ADDR = "127.0.0.1";
pub const LOOPBACK_NETMASK = "255.0.0.0";

pub const ETHER_TAP_NAME = "tap0";
// Scope of EUI-48 Documentation Values.
//  - see https://tools.ietf.org/html/rfc7042
pub const ETHER_TAP_HW_ADDR = "00:00:5e:00:53:01";
// Scope of Documentation Address Blocks (TEST-NET-1).
//  - see https://tools.ietf.org/html/rfc5737
pub const ETHER_TAP_IP_ADDR = "192.0.2.2";
pub const ETHER_TAP_NETMASK = "255.255.255.0";

pub const DEFAULT_GATEWAY = "192.0.2.1";

pub const test_data = [_]u8{
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

var terminate = std.atomic.Value(bool).init(false);

fn onSignal(signum: std.posix.SIG) callconv(.c) void {
    _ = signum;
    terminate.store(true, .seq_cst);
}

fn setup() !void {
    var sa: std.posix.Sigaction = .{
        .handler = .{ .handler = onSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &sa, null);
    util.infof(@src(), "setup protocol stack...", .{});
    net.init() catch |err| {
        util.errorf(@src(), "net.init() failure: {t}", .{err});
        return err;
    };
    const dev = loopback.init() catch |err| {
        util.errorf(@src(), "loopback.init() failure: {t}", .{err});
        return err;
    };
    const allocator = platform.allocator;
    const unicast = ip.IpAddr.fromString(LOOPBACK_IP_ADDR) catch |err| {
        util.errorf(@src(), "IpAddr.fromString() failure: {t}", .{err});
        return err;
    };
    const netmask = ip.IpAddr.fromString(LOOPBACK_NETMASK) catch |err| {
        util.errorf(@src(), "IpAddr.fromString() failure: {t}", .{err});
        return err;
    };
    const iface = ip.IpIface.create(allocator, unicast, netmask) catch |err| {
        util.errorf(@src(), "IpIface.create() failure: {t}", .{err});
        return err;
    };
    ip.registerIface(dev, iface) catch |err| {
        util.errorf(@src(), "ip.registerIface() failure: {t}", .{err});
        return err;
    };
    net.run() catch |err| {
        util.errorf(@src(), "net.run() failure: {t}", .{err});
        return err;
    };
}

fn cleanup() !void {
    util.infof(@src(), "cleanup protocol stack...", .{});
    net.shutdown() catch |err| {
        util.errorf(@src(), "net.shutdown() failure: {t}", .{err});
        return err;
    };
}

fn appMain(io: std.Io) !void {
    const src = ip.IpAddr.fromString(LOOPBACK_IP_ADDR) catch |err| {
        util.errorf(@src(), "IpAddr.fromString() failure: {t}", .{err});
        return err;
    };
    const dst = src;
    const id: u16 = @intCast(std.os.linux.getpid());
    const data: []const u8 = "TEST";
    var seq: u16 = 0;

    util.debugf(@src(), "press Ctrl+C to terminate", .{});
    while (!terminate.load(.seq_cst)) {
        seq += 1;
        _ = icmp.output(.{ .echo = .{ .id = id, .seq = seq } }, data, src, dst) catch |err| {
            util.errorf(@src(), "ip.output() failure: {t}", .{err});
            return err;
        };
        try io.sleep(.fromSeconds(1), .awake);
    }
    util.debugf(@src(), "terminate", .{});
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    try setup();
    try appMain(io);
    try cleanup();
}
