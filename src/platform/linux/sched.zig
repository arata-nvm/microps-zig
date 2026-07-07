const std = @import("std");

const intr = @import("intr.zig");
const platform = @import("platform.zig");
const util = @import("../../util.zig");

pub const Task = struct {
    next: ?*Task = null,
    cond: std.c.pthread_cond_t = .{},
    interrupted: bool = false,
    wc: u32 = 0, // wait count

    pub fn destroy(self: *Task) !void {
        if (self.wc != 0) {
            return error.Busy;
        }
        _ = std.c.pthread_cond_destroy(&self.cond);
    }
};

var lock: platform.Lock = .{};
var tasks: ?*Task = null; // sleep tasks

fn tasksAdd(task: *Task) void {
    lock.acquire();
    defer lock.release();
    task.next = tasks;
    tasks = task;
}

fn tasksDel(task: *Task) void {
    lock.acquire();
    defer lock.release();
    if (tasks == task) {
        tasks = task.next;
        task.next = null;
        return;
    }
    var entry = tasks;
    while (entry) |e| : (entry = e.next) {
        if (e.next == task) {
            e.next = task.next;
            task.next = null;
            break;
        }
    }
}

/// NOTE: This function is not thread-safe. The caller must hold the mutex before calling this function.
pub fn taskSleep(task: *Task, mutex: *platform.Lock, abstime: ?*const std.c.timespec) error{ Interrupted, Timeout }!void {
    if (task.interrupted) {
        return error.Interrupted;
    }
    task.wc += 1;
    tasksAdd(task);
    var timed_out = false;
    if (abstime) |ts| {
        timed_out = std.c.pthread_cond_timedwait(&task.cond, &mutex.inner, ts) == .TIMEDOUT;
    } else {
        _ = std.c.pthread_cond_wait(&task.cond, &mutex.inner);
    }
    tasksDel(task);
    task.wc -= 1;
    if (task.interrupted) {
        if (task.wc == 0) {
            task.interrupted = false;
        }
        return error.Interrupted;
    }
    if (timed_out) {
        return error.Timeout;
    }
}

pub fn taskWakeup(task: *Task) void {
    _ = std.c.pthread_cond_broadcast(&task.cond);
}

fn schedIrqHandler(irq: u32, arg: ?*anyopaque) void {
    _ = irq;
    _ = arg;
    lock.acquire();
    defer lock.release();
    var task = tasks;
    while (task) |t| : (task = t.next) {
        if (!t.interrupted) {
            t.interrupted = true;
            _ = std.c.pthread_cond_broadcast(&t.cond);
        }
    }
}

pub fn init() !void {
    try intr.register(intr.irq_user, schedIrqHandler, 0, null);
}

pub fn run() !void {
    // do nothing
}

pub fn shutdown() !void {
    // do nothing
}
