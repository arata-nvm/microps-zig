const std = @import("std");

const intr = @import("intr.zig");
const platform = @import("platform.zig");
const util = @import("../../util.zig");

const timer_t = ?*anyopaque;
const sigevent = extern struct {
    value: extern union {
        int: c_int,
        ptr: ?*anyopaque,
    },
    signo: c_int,
    notify: c_int,
    _pad: [48]u8,
};
const SIGEV_SIGNAL: c_int = 0;
extern "c" fn timer_create(clockid: std.c.clockid_t, sevp: ?*sigevent, timerid: *timer_t) c_int;
extern "c" fn timer_settime(timerid: timer_t, flags: c_int, new_value: *const std.c.itimerspec, old_value: ?*std.c.itimerspec) c_int;
extern "c" fn timer_delete(timerid: timer_t) c_int;

const Timer = struct {
    interval: std.c.timeval,
    last: std.c.timeval,
    handler: *const fn () void,
};

var timerid: timer_t = undefined;

/// NOTE: if you want to add/delete the entries after timer_run(), you need to protect these lists with a mutex.
var timers: std.ArrayList(*Timer) = .empty;

pub fn register(interval: std.c.timeval, handler: *const fn () void) !void {
    const allocator = platform.allocator;
    const timer = try allocator.create(Timer);
    var last: std.c.timeval = undefined;
    _ = std.c.gettimeofday(&last, null);
    timer.* = .{
        .interval = interval,
        .last = last,
        .handler = handler,
    };
    try timers.append(allocator, timer);
    util.infof(@src(), "success, interval={{{d}, {d}}}", .{ interval.sec, interval.usec });
}

fn timerIrqHandler(irq: u32, arg: ?*anyopaque) !void {
    _ = irq;
    _ = arg;
    var now: std.c.timeval = undefined;
    _ = std.c.gettimeofday(&now, null);
    for (timers.items) |t| {
        const diff = util.timevalSub(now, t.last);
        if (util.timevalCmp(t.interval, diff) < 0) {
            t.handler();
            t.last = now;
        }
    }
}

pub fn init() !void {
    var sev: sigevent = .{
        .value = .{ .ptr = @ptrCast(&timerid) },
        .signo = @intCast(intr.irq_timer),
        .notify = SIGEV_SIGNAL,
        ._pad = @splat(0),
    };
    if (timer_create(.REALTIME, &sev, &timerid) == -1) {
        util.errorf(@src(), "timer_create: failure", .{});
        return error.TimerCreateFailure;
    }
    try intr.register(intr.irq_timer, timerIrqHandler, .{}, null);
}

pub fn run() !void {
    const ts: std.c.timespec = .{ .sec = 0, .nsec = 1000000 }; // 1ms
    const interval: std.c.itimerspec = .{ .it_interval = ts, .it_value = ts };
    if (timer_settime(timerid, 0, &interval, null) == -1) {
        util.errorf(@src(), "timer_settime: failure", .{});
        return error.TimerSettimeFailure;
    }
    util.infof(@src(), "interval={{{d}, {d}}}, initial={{{d}, {d}}}", .{
        interval.it_interval.sec, interval.it_interval.nsec,
        interval.it_value.sec,    interval.it_value.nsec,
    });
}

pub fn shutdown() !void {
    if (timer_delete(timerid) == -1) {
        util.errorf(@src(), "timer_delete: failure", .{});
        return error.TimerDeleteFailure;
    }
}

test "periodic timer" {
    const Context = struct {
        var count = std.atomic.Value(u32).init(0);

        fn handler() void {
            _ = count.fetchAdd(1, .seq_cst);
        }
    };

    try intr.init();
    try init();
    try register(.{ .sec = 0, .usec = 10 * std.time.us_per_ms }, Context.handler);
    try intr.run();
    try run();
    var retry: usize = 0;
    while (Context.count.load(.seq_cst) < 3 and retry < 1000) : (retry += 1) {
        const ts: std.c.timespec = .{ .sec = 0, .nsec = std.time.ns_per_ms };
        _ = std.c.nanosleep(&ts, null);
    }
    try shutdown();
    try intr.shutdown();
    try std.testing.expect(Context.count.load(.seq_cst) >= 3);
}
