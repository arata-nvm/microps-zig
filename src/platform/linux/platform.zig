const std = @import("std");

const net = @import("../../net.zig");

const linux = std.os.linux;

pub const intr = @import("intr.zig");
pub const timer = @import("timer.zig");
pub const sched = @import("sched.zig");

pub const driver = struct {
    pub const ether_tap = @import("driver/ether_tap.zig");
};

pub const InitOptions = struct {
    gpa: std.mem.Allocator = std.heap.c_allocator,
};

pub var allocator: std.mem.Allocator = std.heap.c_allocator;
var started: std.Io.Timestamp = .zero;

var initialized: bool = false;

pub fn init(options: InitOptions) !void {
    if (initialized) {
        return;
    }
    initialized = true;

    allocator = options.gpa;
    started = now();

    try intr.init();
    try intr.registerNoarg(intr.irq_soft, net.sortirqHandler, .{});
    try timer.init();
    try sched.init();
}

pub fn run() !void {
    try intr.run();
    try timer.run();
    try sched.run();
}

pub fn shutdown() !void {
    try intr.shutdown();
    try timer.shutdown();
    try sched.shutdown();
}

pub const Lock = struct {
    inner: std.c.pthread_mutex_t = .{},

    pub fn acquire(self: *Lock) void {
        _ = std.c.pthread_mutex_lock(&self.inner);
    }

    pub fn release(self: *Lock) void {
        _ = std.c.pthread_mutex_unlock(&self.inner);
    }
};

pub fn now() std.Io.Timestamp {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return .{ .nanoseconds = @as(i96, ts.sec) * std.time.ns_per_s + @as(i96, ts.nsec) };
}

pub fn random16() u16 {
    var b: [2]u8 = undefined;
    _ = linux.getrandom(&b, b.len, 0);
    return @bitCast(b);
}

pub fn random32() u32 {
    var b: [4]u8 = undefined;
    _ = linux.getrandom(&b, b.len, 0);
    return @bitCast(b);
}

pub fn log(bytes: []const u8) void {
    var buffer: [64]u8 = undefined;
    const stderr = std.debug.lockStderr(&buffer);
    defer std.debug.unlockStderr();
    stderr.file_writer.interface.writeAll(bytes) catch {};
}

pub fn uptime() std.Io.Duration {
    if (!initialized) return .zero;
    return started.durationTo(now());
}
