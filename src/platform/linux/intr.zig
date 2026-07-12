const std = @import("std");

const platform = @import("platform.zig");
const util = @import("../../util.zig");

pub const irq_soft: u32 = @intFromEnum(std.c.SIG.USR1);
pub const irq_user: u32 = @intFromEnum(std.c.SIG.USR2);
pub const irq_timer: u32 = @intFromEnum(std.c.SIG.ALRM);

pub fn irqBase() u32 {
    return @as(u32, std.c.sigrtmin()) + 1;
}

pub const Isr = *const fn (irq: u32, arg: ?*anyopaque) anyerror!void;

pub const IrqFlags = struct {
    shared: bool = false,
};

const IrqEntry = struct {
    irq: u32,
    isr: Isr,
    flags: IrqFlags,
    arg: ?*anyopaque,
};

/// NOTE: if you want to add/delete the entries after run(), you need to protect these lists with a mutex.
var irqs: std.ArrayList(IrqEntry) = .empty;

var thread: ?std.Thread = null;
var barrier: std.c.sem_t = undefined;
var sigmask: std.c.sigset_t = undefined;

pub fn registerNoarg(irq: u32, isr: fn (u32) anyerror!void, flags: IrqFlags) !void {
    const Shim = struct {
        fn call(i: u32, arg: ?*anyopaque) !void {
            _ = arg;
            try isr(i);
        }
    };
    return register(irq, Shim.call, flags, null);
}

pub fn registerTyped(comptime Ctx: type, irq: u32, comptime isr: fn (u32, *Ctx) anyerror!void, flags: IrqFlags, ctx: *Ctx) !void {
    const Shim = struct {
        fn call(i: u32, arg: ?*anyopaque) !void {
            try isr(i, @ptrCast(@alignCast(arg.?)));
        }
    };
    return register(irq, Shim.call, flags, ctx);
}

pub fn register(irq: u32, isr: Isr, flags: IrqFlags, arg: ?*anyopaque) !void {
    for (irqs.items) |e| {
        if (e.irq == irq) {
            if (!e.flags.shared or !flags.shared) {
                util.errorf(@src(), "conflicts with already registered IRQs, irq={d}", .{irq});
                return error.IrqConflict;
            }
        }
    }

    const allocator = platform.allocator;
    try irqs.append(allocator, .{
        .irq = irq,
        .isr = isr,
        .flags = flags,
        .arg = arg,
    });
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
        if (irq != irq_timer) {
            util.debugf(@src(), "IRQ <{d}> occurred", .{irq});
        }
        for (irqs.items) |e| {
            if (e.irq == irq) {
                e.isr(e.irq, e.arg) catch |err2| {
                    util.errorf(@src(), "ISR failure, irq={d}, err={t}", .{ irq, err2 });
                };
                if (!e.flags.shared) {
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

        fn isr(irq: u32, arg: ?*anyopaque) !void {
            _ = irq;
            _ = arg;
            called.store(true, .seq_cst);
        }
    };

    try platform.init(.{ .io = std.testing.io });
    try register(irqBase(), Context.isr, .{}, null);
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
