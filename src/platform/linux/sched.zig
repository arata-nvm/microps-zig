const std = @import("std");

const intr = @import("intr.zig");
const platform = @import("platform.zig");
const util = @import("../../util.zig");

var sleeping_tasks: TaskList = .{};

const TaskList = struct {
    const Self = @This();

    lock: platform.Lock = .{},
    tasks: std.ArrayList(*Task) = .empty,

    fn add(self: *Self, task: *Task) !void {
        self.lock.acquire();
        defer self.lock.release();

        try self.tasks.append(platform.allocator, task);
    }

    fn delete(self: *Self, task: *Task) !void {
        self.lock.acquire();
        defer self.lock.release();

        const i = std.mem.indexOfScalar(*Task, self.tasks.items, task) orelse return error.NotFound;
        _ = self.tasks.swapRemove(i);
    }

    fn interrupt(self: *Self) void {
        self.lock.acquire();
        defer self.lock.release();

        for (self.tasks.items) |task| {
            if (!task.interrupted) {
                task.interrupted = true;
                _ = std.c.pthread_cond_broadcast(&task.cond);
            }
        }
    }
};

pub const Task = struct {
    cond: std.c.pthread_cond_t = .{},
    interrupted: bool = false,
    wc: u32 = 0, // wait count

    pub fn wakeup(self: *Task) void {
        _ = std.c.pthread_cond_broadcast(&self.cond);
    }

    /// NOTE: This function is not thread-safe. The caller must hold the mutex before calling this function.
    pub fn sleep(self: *Task, mutex: *platform.Lock, timeout: ?std.Io.Duration) !void {
        if (self.interrupted) {
            return error.Interrupted;
        }

        var timed_out = false;
        {
            self.wc += 1;
            defer self.wc -= 1;

            try sleeping_tasks.add(self);
            if (timeout) |d| {
                var ts: std.c.timespec = undefined;
                _ = std.c.clock_gettime(.REALTIME, &ts);
                const total = ts.sec * std.time.ns_per_s + ts.nsec + d.toNanoseconds();
                const abs: std.c.timespec = .{
                    .sec = @intCast(@divTrunc(total, std.time.ns_per_s)),
                    .nsec = @intCast(@mod(total, std.time.ns_per_s)),
                };
                timed_out = std.c.pthread_cond_timedwait(&self.cond, &mutex.inner, &abs) == .TIMEDOUT;
            } else {
                _ = std.c.pthread_cond_wait(&self.cond, &mutex.inner);
            }
            try sleeping_tasks.delete(self);
        }

        if (self.interrupted) {
            if (self.wc == 0) {
                self.interrupted = false;
            }
            return error.Interrupted;
        }
        if (timed_out) {
            return error.Timeout;
        }
    }

    pub fn destroy(self: *Task) error{Busy}!void {
        if (self.wc != 0) {
            return error.Busy;
        }
        _ = std.c.pthread_cond_destroy(&self.cond);
    }
};

fn irqHandler(_: u32) void {
    sleeping_tasks.interrupt();
}

pub fn init() !void {
    try intr.registerNoarg(intr.irq_user, irqHandler, .{});
}

pub fn run() !void {
    // do nothing
}

pub fn shutdown() !void {
    // do nothing
}
