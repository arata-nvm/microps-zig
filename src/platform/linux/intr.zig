const std = @import("std");

const platform = @import("platform.zig");
const util = @import("../../util.zig");

pub const IRQ_SOFT: u32 = @intFromEnum(std.c.SIG.USR1);
pub const IRQ_USER: u32 = @intFromEnum(std.c.SIG.USR2);
pub const IRQ_TIMER: u32 = @intFromEnum(std.c.SIG.ALRM);

pub fn irqBase() u32 {
    return @as(u32, std.c.sigrtmin()) + 1;
}

pub const IRQ_SHARED: u32 = 0x0001;

pub const Isr = *const fn (irq: u32, arg: ?*anyopaque) void;

const IrqEntry = struct {
    next: ?*IrqEntry,
    irq: u32,
    isr: Isr,
    flags: u32,
    arg: ?*anyopaque,
};

/// NOTE: if you want to add/delete the entries after run(), you need to protect these lists with a mutex.
var irqs: ?*IrqEntry = null;

var thread: ?std.Thread = null;
var barrier: std.c.sem_t = undefined;
var sigmask: std.c.sigset_t = undefined;

pub fn register(irq: u32, isr: Isr, flags: u32, arg: ?*anyopaque) !void {
    var entry = irqs;
    while (entry) |e| : (entry = e.next) {
        if (e.irq == irq) {
            if (e.flags != IRQ_SHARED or flags != IRQ_SHARED) {
                util.errorf(@src(), "conflicts with already registered IRQs, irq={d}", .{irq});
                return error.IrqConflict;
            }
        }
    }
    const new = try platform.allocator.create(IrqEntry);
    new.* = .{
        .next = irqs,
        .irq = irq,
        .isr = isr,
        .flags = flags,
        .arg = arg,
    };
    irqs = new;
    std.posix.sigaddset(&sigmask, @enumFromInt(irq));
    util.infof(@src(), "success, irq={d}", .{irq});
}

pub fn raise(irq: u32) !void {
    const t = thread orelse return error.NotRunning;
    if (std.c.pthread_kill(t.getHandle(), @enumFromInt(irq)) != 0) {
        return error.RaiseFailure;
    }
}

fn intrMain() void {
    util.infof(@src(), "start...", .{});
    _ = std.c.sem_post(&barrier);
    var terminate = false;
    while (!terminate) {
        var sig: c_int = undefined;
        const err = std.c.sigwait(&sigmask, &sig);
        if (err != 0) {
            util.errorf(@src(), "sigwait() failure, err={d}", .{err});
            break;
        }
        if (sig == @intFromEnum(std.c.SIG.HUP)) {
            terminate = true;
            continue;
        }
        const irq: u32 = @intCast(sig);
        if (irq != IRQ_TIMER) {
            util.debugf(@src(), "IRQ <{d}> occurred", .{irq});
        }
        var entry = irqs;
        while (entry) |e| : (entry = e.next) {
            if (e.irq == irq) {
                e.isr(e.irq, e.arg);
                if (e.flags != IRQ_SHARED) {
                    break;
                }
            }
        }
    }
    util.infof(@src(), "terminated", .{});
}

pub fn init() !void {
    if (std.c.sem_init(&barrier, 0, 0) != 0) {
        return error.SemInitFailure;
    }
    sigmask = std.posix.sigemptyset();
    std.posix.sigaddset(&sigmask, .HUP);
}

pub fn run() !void {
    var oldset: std.c.sigset_t = undefined;
    const err = std.c.pthread_sigmask(std.c.SIG.BLOCK, &sigmask, &oldset);
    if (err != 0) {
        util.errorf(@src(), "pthread_sigmask() failure, err={d}", .{err});
        return error.SigmaskFailure;
    }
    thread = try std.Thread.spawn(.{}, intrMain, .{});
    _ = std.c.sem_wait(&barrier);
}

pub fn shutdown() !void {
    const t = thread orelse {
        return error.NotRunning;
    };
    _ = std.c.pthread_kill(t.getHandle(), .HUP);
    t.join();
    thread = null;
}

test "raise and dispatch" {
    const Context = struct {
        var called = std.atomic.Value(bool).init(false);

        fn isr(irq: u32, arg: ?*anyopaque) void {
            _ = irq;
            _ = arg;
            called.store(true, .seq_cst);
        }
    };

    try init();
    try register(irqBase(), Context.isr, 0, null);
    try run();
    try raise(irqBase());
    var retry: usize = 0;
    while (!Context.called.load(.seq_cst) and retry < 1000) : (retry += 1) {
        const ts: std.c.timespec = .{ .sec = 0, .nsec = std.time.ns_per_ms };
        _ = std.c.nanosleep(&ts, null);
    }
    try shutdown();
    try std.testing.expect(Context.called.load(.seq_cst));
}
