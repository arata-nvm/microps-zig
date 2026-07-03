const std = @import("std");

pub const intr = @import("intr.zig");
pub const timer = @import("timer.zig");
pub const sched = @import("sched.zig");

pub fn init() !void {}

pub fn run() !void {}

pub fn shutdown() !void {}

pub const allocator = std.heap.c_allocator;

pub const Lock = struct {
    inner: std.c.pthread_mutex_t = .{},

    pub fn acquire(self: *Lock) void {
        _ = std.c.pthread_mutex_lock(&self.inner);
    }

    pub fn release(self: *Lock) void {
        _ = std.c.pthread_mutex_unlock(&self.inner);
    }
};

pub fn random16() u16 {
    return std.crypto.random.int(u16);
}
