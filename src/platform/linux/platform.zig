const std = @import("std");

const net = @import("../../net.zig");

pub const intr = @import("intr.zig");
pub const timer = @import("timer.zig");
pub const sched = @import("sched.zig");

pub const driver = struct {
    pub const ether_tap = @import("driver/ether_tap.zig");
};

pub const InitOptions = struct {
    io: std.Io,
    gpa: std.mem.Allocator = std.heap.c_allocator,
};

var io: ?std.Io = null;
pub var allocator: std.mem.Allocator = undefined;
var started: std.Io.Timestamp = .zero;

var initialized: bool = false;

pub fn init(options: InitOptions) !void {
    if (initialized) {
        return;
    }
    initialized = true;

    io = options.io;
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
    const i = io orelse return .zero;
    return .now(i, .awake);
}

pub fn random16() u16 {
    const i = io orelse return 0;
    var b: [2]u8 = undefined;
    i.random(&b);
    return @bitCast(b);
}

pub fn random32() u32 {
    const i = io orelse return 0;
    var b: [4]u8 = undefined;
    i.random(&b);
    return @bitCast(b);
}

pub fn log(bytes: []const u8) void {
    var buffer: [64]u8 = undefined;
    const stderr = std.debug.lockStderr(&buffer);
    defer std.debug.unlockStderr();
    stderr.file_writer.interface.writeAll(bytes) catch {};
}

pub fn uptime() std.Io.Duration {
    return started.durationTo(now());
}
