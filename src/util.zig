const std = @import("std");
const build_options = @import("build_options");

const platform = @import("platform.zig");

fn output(comptime fmt: []const u8, args: anytype) void {
    var buffer: [1024]u8 = undefined;
    var w = std.Io.Writer.fixed(&buffer);
    w.print(fmt, args) catch {};
    platform.log(w.buffered());
}

pub fn logf(level: u8, src: std.builtin.SourceLocation, comptime fmt: []const u8, args: anytype) void {
    const up = platform.uptime();
    const s: u64 = @intCast(up.toSeconds());
    const ms: u64 = @intCast(up.toMilliseconds());
    output("{d:0>2}:{d:0>2}.{d:0>3} [{c}] {s:<16}: " ++ fmt ++ " ({s}:{d})\n", .{
        s / 60,
        s % 60,
        ms % 1000,
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

pub fn hexdump(writer: *std.Io.Writer, data: []const u8) !void {
    try writer.print("+------+-------------------------------------------------+------------------+\n", .{});
    var chunks = std.mem.window(u8, data, 16, 16);
    var offset: usize = 0;
    while (chunks.next()) |chunk| : (offset += 16) {
        try writer.print("| {x:0>4} | ", .{offset});

        for (chunk) |c| {
            try writer.print("{x:0>2} ", .{c});
        }
        try writer.splatBytesAll("   ", 16 - chunk.len);

        try writer.print("| ", .{});

        for (chunk) |c| {
            try writer.print("{c}", .{if (std.ascii.isPrint(c)) c else '.'});
        }
        try writer.splatBytesAll(" ", 16 - chunk.len);

        try writer.print(" |\n", .{});
    }
    try writer.print("+------+-------------------------------------------------+------------------+\n", .{});
}

var dump_buf_lock: platform.Lock = .{};
var dump_buf: [8192]u8 = undefined;

pub fn debugdump(data: []const u8) void {
    if (!build_options.hexdump) {
        return;
    }

    dump_buf_lock.acquire();
    defer dump_buf_lock.release();

    var w = std.Io.Writer.fixed(&dump_buf);
    hexdump(&w, data) catch {};
    platform.log(w.buffered());
}

pub fn dumpf(comptime fmt: []const u8, args: anytype) void {
    output(fmt, args);
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

        pub fn push(self: *Self, data: T) !void {
            const allocator = platform.allocator();
            const entry = try allocator.create(Entry);
            entry.* = .{
                .next = null,
                .data = data,
            };

            if (self.head == null) {
                self.head = entry;
            }

            if (self.tail) |tail| {
                tail.next = entry;
            }
            self.tail = entry;

            self.num += 1;
        }

        pub fn pop(self: *Self) ?T {
            const entry = self.head orelse return null;
            const data = entry.data;

            self.head = entry.next;
            if (self.head == null) {
                self.tail = null;
            }
            self.num -= 1;

            const allocator = platform.allocator();
            allocator.destroy(entry);

            return data;
        }

        pub fn peek(self: *Self) ?T {
            const head = self.head orelse return null;
            return head.data;
        }

        pub const Iterator = struct {
            entry: ?*Entry,

            pub fn next(self: *Iterator) ?*T {
                const entry = self.entry orelse return null;
                self.entry = entry.next;
                return &entry.data;
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
        sum += @as(u16, data[i]) << 8;
    }
    while (sum >> 16 != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~@as(u16, @truncate(sum));
}

test "queue" {
    const Q = Queue(u32);
    var queue: Q = .{};
    var entries = [_]u32{ 1, 2, 3 };

    try std.testing.expectEqual(null, queue.pop());
    for (&entries) |entry| {
        try queue.push(entry);
    }
    try std.testing.expectEqual(3, queue.num);
    try std.testing.expectEqual(1, queue.peek().?);

    var it = queue.iterator();
    var expected: u32 = 1;
    while (it.next()) |entry| : (expected += 1) {
        try std.testing.expectEqual(expected, entry.*);
    }

    try std.testing.expectEqual(1, queue.pop().?);
    try std.testing.expectEqual(2, queue.pop().?);
    try std.testing.expectEqual(3, queue.pop().?);
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
