const std = @import("std");

const microps = @import("microps");

const platform = microps.platform;
const tcp = microps.tcp;
const udp = microps.udp;
const util = microps.util;

const c = @cImport({
    @cInclude("sock.h");
});

const sock = struct {
    used: bool = false,
    family: usize = 0,
    type: usize = 0,
    desc: usize = 0,
};

var lock: platform.Lock = .{};
var socks: [32]sock = @splat(.{});

fn sock_alloc() ?*sock {
    for (&socks) |*entry| {
        if (!entry.used) {
            entry.used = true;
            return entry;
        }
    }
    return null;
}

fn sock_desc(s: *sock) c_int {
    return @intCast(@divExact(@intFromPtr(s) - @intFromPtr(&socks), @sizeOf(sock)));
}

fn sock_free(s: *sock) void {
    s.* = .{};
}

fn sock_get(desc: c_int) ?*sock {
    if (desc < 0 or desc >= socks.len) return null;
    return &socks[@intCast(desc)];
}

export fn sock_open(domain: c_int, typ: c_int, protocol: c_int) c_int {
    if (domain != c.AF_INET) return -1;
    switch (typ) {
        c.SOCK_STREAM => if (protocol != 0 and protocol != c.IPPROTO_TCP) return -1,
        c.SOCK_DGRAM => if (protocol != 0 and protocol != c.IPPROTO_UDP) return -1,
        else => return -1,
    }

    lock.acquire();
    defer lock.release();

    const s = sock_alloc() orelse return -1;
    s.* = .{
        .used = true,
        .family = @intCast(domain),
        .type = @intCast(typ),
        .desc = switch (s.type) {
            c.SOCK_STREAM => tcp.cmd.socket() catch return -1,
            c.SOCK_DGRAM => udp.cmd.open() catch return -1,
            else => return -1,
        },
    };

    return sock_desc(s);
}

export fn sock_close(desc: c_int) c_int {
    lock.acquire();
    defer lock.release();

    const s = sock_get(desc) orelse return -1;
    switch (s.family) {
        c.AF_INET => switch (s.type) {
            c.SOCK_STREAM => tcp.cmd.close(s.desc) catch {},
            c.SOCK_DGRAM => udp.cmd.close(s.desc) catch {},
            else => util.warnf(@src(), "unknown type {d}", .{s.type}),
        },
        else => util.errorf(@src(), "unknown family {d}", .{s.family}),
    }
    sock_free(s);
    return 0;
}

export fn sock_recvfrom(desc: c_int, buf: *anyopaque, n: usize, addr: ?*c.sockaddr, addrlen: ?*c_int) isize {
    const s = blk: {
        lock.acquire();
        defer lock.release();

        const s = sock_get(desc) orelse return -1;
        break :blk s.*;
    };

    switch (s.family) {
        c.AF_INET => switch (s.type) {
            c.SOCK_DGRAM => {
                const b = @as([*]u8, @ptrCast(buf))[0..n];
                const ret = udp.cmd.recvfrom(s.desc, b) catch return -1;
                if (addr) |a| {
                    if (addrlen) |al| {
                        const p: *c.sockaddr_in = @ptrCast(@alignCast(a));
                        p.sin_addr.s_addr = std.mem.nativeToBig(u32, ret.remote.addr.toU32());
                        p.sin_port = std.mem.nativeToBig(u16, @intFromEnum(ret.remote.port));
                        al.* = @sizeOf(c.sockaddr_in);
                    }
                }
                return @intCast(ret.len);
            },
            else => {
                util.errorf(@src(), "unsupported type {d}", .{s.type});
                return -1;
            },
        },
        else => {
            util.errorf(@src(), "unsupported family {d}", .{s.family});
            return -1;
        },
    }
}

export fn sock_sendto(desc: c_int, buf: ?*const anyopaque, n: usize, addr: *c.sockaddr, _: c_int) isize {
    const s = blk: {
        lock.acquire();
        defer lock.release();

        const s = sock_get(desc) orelse return -1;
        break :blk s.*;
    };

    switch (s.family) {
        c.AF_INET => switch (s.type) {
            c.SOCK_DGRAM => {
                const b = @as([*]const u8, @ptrCast(buf))[0..n];
                const p: *c.sockaddr_in = @ptrCast(@alignCast(addr));
                const remote: udp.SocketAddr = .{
                    .addr = .fromU32(std.mem.bigToNative(u32, p.sin_addr.s_addr)),
                    .port = @enumFromInt(std.mem.bigToNative(u16, p.sin_port)),
                };
                const sent = udp.cmd.sendto(s.desc, b, remote) catch return -1;
                return @intCast(sent);
            },
            else => {
                util.errorf(@src(), "unsupported type {d}", .{s.type});
                return -1;
            },
        },
        else => {
            util.errorf(@src(), "unsupported family {d}", .{s.family});
            return -1;
        },
    }
}

export fn sock_bind(desc: c_int, addr: *c.sockaddr, _: c_int) c_int {
    const s = blk: {
        lock.acquire();
        defer lock.release();

        const s = sock_get(desc) orelse return -1;
        break :blk s.*;
    };

    switch (s.family) {
        c.AF_INET => {
            const p: *c.sockaddr_in = @ptrCast(@alignCast(addr));
            const local: udp.SocketAddr = .{
                .addr = .fromU32(std.mem.bigToNative(u32, p.sin_addr.s_addr)),
                .port = @enumFromInt(std.mem.bigToNative(u16, p.sin_port)),
            };
            switch (s.type) {
                c.SOCK_STREAM => {
                    tcp.cmd.bind(s.desc, local) catch return -1;
                    return 0;
                },
                c.SOCK_DGRAM => {
                    udp.cmd.bind(s.desc, local) catch return -1;
                    return 0;
                },
                else => {
                    util.errorf(@src(), "unsupported type {d}", .{s.type});
                    return -1;
                },
            }
        },
        else => {
            util.errorf(@src(), "unsupported family {d}", .{s.family});
            return -1;
        },
    }
}

export fn sock_listen(desc: c_int, backlog: c_int) c_int {
    const s = blk: {
        lock.acquire();
        defer lock.release();

        const s = sock_get(desc) orelse return -1;
        break :blk s.*;
    };

    switch (s.family) {
        c.AF_INET => switch (s.type) {
            c.SOCK_STREAM => {
                tcp.cmd.listen(s.desc, @intCast(backlog)) catch return -1;
                return 0;
            },
            else => {
                util.errorf(@src(), "unsupported type {d}", .{s.type});
                return -1;
            },
        },
        else => {
            util.errorf(@src(), "unsupported family {d}", .{s.family});
            return -1;
        },
    }
}

export fn sock_accept(desc: c_int, addr: ?*c.sockaddr, addrlen: ?*c_int) c_int {
    const s = blk: {
        lock.acquire();
        defer lock.release();

        const s = sock_get(desc) orelse return -1;
        break :blk s.*;
    };

    switch (s.family) {
        c.AF_INET => switch (s.type) {
            c.SOCK_STREAM => {
                const ret = tcp.cmd.accept(s.desc) catch return -1;
                if (addr) |a| {
                    if (addrlen) |al| {
                        const p: *c.sockaddr_in = @ptrCast(@alignCast(a));
                        p.sin_addr.s_addr = std.mem.nativeToBig(u32, ret.remote.addr.toU32());
                        p.sin_port = std.mem.nativeToBig(u16, @intFromEnum(ret.remote.port));
                        al.* = @sizeOf(c.sockaddr_in);
                    }
                }

                lock.acquire();
                defer lock.release();

                const new_s = sock_alloc() orelse return -1;
                new_s.* = .{
                    .used = true,
                    .family = s.family,
                    .type = s.type,
                    .desc = ret.desc,
                };

                return sock_desc(new_s);
            },
            else => {
                util.errorf(@src(), "unsupported type {d}", .{s.type});
                return -1;
            },
        },
        else => {
            util.errorf(@src(), "unsupported family {d}", .{s.family});
            return -1;
        },
    }
}

export fn sock_connect(desc: c_int, addr: *const c.sockaddr, _: c_int) c_int {
    const s = blk: {
        lock.acquire();
        defer lock.release();

        const s = sock_get(desc) orelse return -1;
        break :blk s.*;
    };

    switch (s.family) {
        c.AF_INET => switch (s.type) {
            c.SOCK_STREAM => {
                const p: *const c.sockaddr_in = @ptrCast(@alignCast(addr));
                const remote: udp.SocketAddr = .{
                    .addr = .fromU32(std.mem.bigToNative(u32, p.sin_addr.s_addr)),
                    .port = @enumFromInt(std.mem.bigToNative(u16, p.sin_port)),
                };
                tcp.cmd.connect(s.desc, remote) catch return -1;
                return 0;
            },
            else => {
                util.errorf(@src(), "unsupported type {d}", .{s.type});
                return -1;
            },
        },
        else => {
            util.errorf(@src(), "unsupported family {d}", .{s.family});
            return -1;
        },
    }
}

export fn sock_recv(desc: c_int, buf: *anyopaque, n: usize) isize {
    const s = blk: {
        lock.acquire();
        defer lock.release();

        const s = sock_get(desc) orelse return -1;
        break :blk s.*;
    };

    switch (s.family) {
        c.AF_INET => switch (s.type) {
            c.SOCK_STREAM => {
                const b = @as([*]u8, @ptrCast(buf))[0..n];
                return @intCast(tcp.cmd.receive(s.desc, b) catch return -1);
            },
            else => {
                util.errorf(@src(), "unsupported type {d}", .{s.type});
                return -1;
            },
        },
        else => {
            util.errorf(@src(), "unsupported family {d}", .{s.family});
            return -1;
        },
    }
}

export fn sock_send(desc: c_int, buf: *const anyopaque, n: usize) isize {
    const s = blk: {
        lock.acquire();
        defer lock.release();

        const s = sock_get(desc) orelse return -1;
        break :blk s.*;
    };

    switch (s.family) {
        c.AF_INET => switch (s.type) {
            c.SOCK_STREAM => {
                const b = @as([*]const u8, @ptrCast(buf))[0..n];
                return @intCast(tcp.cmd.send(s.desc, b) catch return -1);
            },
            else => {
                util.errorf(@src(), "unsupported type {d}", .{s.type});
                return -1;
            },
        },
        else => {
            util.errorf(@src(), "unsupported family {d}", .{s.family});
            return -1;
        },
    }
}
