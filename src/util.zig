const std = @import("std");
const build_options = @import("build_options");

pub fn timevalAddUsec(x: *std.c.timeval, usec: i64) void {
    x.sec += @intCast(@divTrunc(usec, std.time.us_per_s));
    x.usec += @intCast(@mod(usec, std.time.us_per_s));
    if (x.usec >= std.time.us_per_s) {
        x.sec += 1;
        x.usec -= std.time.us_per_s;
    }
}

pub fn timespecAddNsec(x: *std.c.timespec, nsec: i64) void {
    x.sec += @intCast(@divTrunc(nsec, std.time.ns_per_s));
    x.nsec += @intCast(@mod(nsec, std.time.ns_per_s));
    if (x.nsec >= std.time.ns_per_s) {
        x.sec += 1;
        x.nsec -= std.time.ns_per_s;
    }
}

pub fn timevalSub(a: std.c.timeval, b: std.c.timeval) std.c.timeval {
    var result: std.c.timeval = .{ .sec = a.sec - b.sec, .usec = a.usec - b.usec };
    if (result.usec < 0) {
        result.sec -= 1;
        result.usec += std.time.us_per_s;
    }
    return result;
}

pub fn timevalCmp(a: std.c.timeval, b: std.c.timeval) i2 {
    if (a.sec != b.sec) {
        return if (a.sec < b.sec) -1 else 1;
    }
    if (a.usec != b.usec) {
        return if (a.usec < b.usec) -1 else 1;
    }
    return 0;
}

const Tm = extern struct {
    sec: c_int,
    min: c_int,
    hour: c_int,
    mday: c_int,
    mon: c_int,
    year: c_int,
    wday: c_int,
    yday: c_int,
    isdst: c_int,
    gmtoff: c_long,
    zone: ?[*:0]const u8,
};
extern "c" fn localtime_r(timep: *const std.c.time_t, result: *Tm) ?*Tm;

pub fn logf(level: u8, src: std.builtin.SourceLocation, comptime fmt: []const u8, args: anytype) void {
    var tv: std.c.timeval = undefined;
    _ = std.c.gettimeofday(&tv, null);
    const sec: std.c.time_t = @intCast(tv.sec);
    var tm: Tm = undefined;
    _ = localtime_r(&sec, &tm);
    std.debug.print("{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3} [{c}] {s}: " ++ fmt ++ " ({s}:{d})\n", .{
        @as(u32, @intCast(tm.hour)),
        @as(u32, @intCast(tm.min)),
        @as(u32, @intCast(tm.sec)),
        @as(u32, @intCast(@divTrunc(tv.usec, 1000))),
        level,
        src.fn_name,
    } ++ args ++ .{ src.file, src.line });
}

pub fn errorf(src: std.builtin.SourceLocation, comptime fmt: []const u8, args: anytype) void {
    logf('E', src, fmt, args);
}

pub fn warnf(src: std.builtin.SourceLocation, comptime fmt: []const u8, args: anytype) void {
    logf('W', src, fmt, args);
}

pub fn infof(src: std.builtin.SourceLocation, comptime fmt: []const u8, args: anytype) void {
    logf('I', src, fmt, args);
}

pub fn debugf(src: std.builtin.SourceLocation, comptime fmt: []const u8, args: anytype) void {
    logf('D', src, fmt, args);
}

pub fn hexdump(writer: anytype, data: []const u8) void {
    writer.print("+------+-------------------------------------------------+------------------+\n", .{});
    var offset: usize = 0;
    while (offset < data.len) : (offset += 16) {
        writer.print("| {x:0>4} | ", .{offset});
        for (0..16) |index| {
            if (offset + index < data.len) {
                writer.print("{x:0>2} ", .{data[offset + index]});
            } else {
                writer.print("   ", .{});
            }
        }
        writer.print("| ", .{});
        for (0..16) |index| {
            if (offset + index < data.len) {
                const c = data[offset + index];
                writer.print("{c}", .{if (std.ascii.isPrint(c)) c else '.'});
            } else {
                writer.print(" ", .{});
            }
        }
        writer.print(" |\n", .{});
    }
    writer.print("+------+-------------------------------------------------+------------------+\n", .{});
}

pub fn debugdump(data: []const u8) void {
    if (build_options.hexdump) {
        hexdump(std.debug, data);
    }
}

pub fn Queue(comptime T: type) type {
    return struct {
        const Self = @This();

        pub const Entry = struct {
            next: ?*Entry = null,
            data: T,
        };

        head: ?*Entry = null,
        tail: ?*Entry = null,
        num: usize = 0,

        pub fn push(self: *Self, entry: *Entry) void {
            entry.next = null;
            if (self.tail) |tail| {
                tail.next = entry;
            }
            self.tail = entry;
            if (self.head == null) {
                self.head = entry;
            }
            self.num += 1;
        }

        pub fn pop(self: *Self) ?*Entry {
            const entry = self.head orelse return null;
            self.head = entry.next;
            if (self.head == null) {
                self.tail = null;
            }
            self.num -= 1;
            return entry;
        }

        pub fn peek(self: *Self) ?*Entry {
            return self.head;
        }

        pub const Iterator = struct {
            entry: ?*Entry,

            pub fn next(self: *Iterator) ?*Entry {
                const entry = self.entry orelse return null;
                self.entry = entry.next;
                return entry;
            }
        };

        pub fn iterator(self: *Self) Iterator {
            return .{ .entry = self.head };
        }
    };
}

/// Checksum (RFC 1071)
pub fn cksum16(data: []const u8, init: u32) u16 {
    var sum: u32 = init;
    var i: usize = 0;
    while (i + 2 <= data.len) : (i += 2) {
        sum += std.mem.readInt(u16, data[i..][0..2], .big);
    }
    if (i < data.len) {
        sum += data[i];
    }
    while (sum >> 16 != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~@as(u16, @truncate(sum));
}

test "queue" {
    const Q = Queue(u32);
    var queue: Q = .{};
    var entries = [_]Q.Entry{ .{ .data = 1 }, .{ .data = 2 }, .{ .data = 3 } };

    try std.testing.expectEqual(null, queue.pop());
    for (&entries) |*entry| {
        queue.push(entry);
    }
    try std.testing.expectEqual(3, queue.num);
    try std.testing.expectEqual(1, queue.peek().?.data);

    var it = queue.iterator();
    var expected: u32 = 1;
    while (it.next()) |entry| : (expected += 1) {
        try std.testing.expectEqual(expected, entry.data);
    }

    try std.testing.expectEqual(1, queue.pop().?.data);
    try std.testing.expectEqual(2, queue.pop().?.data);
    try std.testing.expectEqual(3, queue.pop().?.data);
    try std.testing.expectEqual(null, queue.pop());
    try std.testing.expectEqual(0, queue.num);
}

test "cksum16" {
    const ip_header = [_]u8{
        0x45, 0x00, 0x00, 0x30, 0x00, 0x80, 0x00, 0x00, 0xff, 0x01,
        0xbd, 0x4a, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
    };
    try std.testing.expectEqual(@as(u16, 0), cksum16(&ip_header, 0));
}
