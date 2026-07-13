const std = @import("std");

const impl = @import("platform/linux/platform.zig");

pub const InitOptions = impl.InitOptions;
pub const init = impl.init;
pub const run = impl.run;
pub const shutdown = impl.shutdown;
pub const Lock = impl.Lock;
pub const now = impl.now;
pub const uptime = impl.uptime;
pub const random16 = impl.random16;
pub const random32 = impl.random32;
pub const log = impl.log;
pub const timer = impl.timer;
pub const sched = impl.sched;
pub const intr = impl.intr;
pub const driver = impl.driver;

pub fn allocator() std.mem.Allocator {
    return impl.allocator;
}
