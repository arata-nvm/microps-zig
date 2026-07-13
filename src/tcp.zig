const std = @import("std");

const ip = @import("ip.zig");
const platform = @import("platform.zig");
const udp = @import("udp.zig");
const util = @import("util.zig");

const sched = platform.sched;

const TcpFlags = packed struct(u8) {
    fin: bool = false,
    syn: bool = false,
    rst: bool = false,
    psh: bool = false,
    ack: bool = false,
    urg: bool = false,
    zero: u2 = 0,

    pub fn format(
        self: @This(),
        writer: *std.Io.Writer,
    ) !void {
        try writer.print("{c}{c}{c}{c}{c}{c}", .{
            @as(u8, if (self.urg) 'U' else '-'),
            @as(u8, if (self.ack) 'A' else '-'),
            @as(u8, if (self.psh) 'P' else '-'),
            @as(u8, if (self.rst) 'R' else '-'),
            @as(u8, if (self.syn) 'S' else '-'),
            @as(u8, if (self.fin) 'F' else '-'),
        });
    }
};

const TcpOptionKind = enum(u8) {
    end_of_option_list = 0,
    no_operation = 1,
    maximum_segment_size = 2,
    window_scale = 3,
    sack_permitted = 4,
    sack = 5,
    timestamps = 8,
    unknown,
};

const TcpOption = union(TcpOptionKind) {
    end_of_option_list: void,
    no_operation: void,
    maximum_segment_size: struct { mss: u16 },
    window_scale: void,
    sack_permitted: void,
    sack: void,
    timestamps: void,
    unknown: struct { kind: u8, len: u8 },
};

const TcpHdr = struct {
    const Self = @This();

    const hdr_len_min = 20;

    src: udp.SocketAddr,
    dst: udp.SocketAddr,
    seq: u32,
    ack: u32,
    off_4byte: u4,
    flg: TcpFlags,
    wnd: u16,
    sum: u16 = 0,
    up: u16,
    opts: std.ArrayList(TcpOption) = .empty,

    pub const Decoded = struct {
        hdr: Self,
        payload: []const u8,
    };

    pub fn decode(data: []const u8, ip_hdr: *const ip.IpHdr) !Decoded {
        var r: std.Io.Reader = .fixed(data);
        var hdr: TcpHdr = .{
            .src = .{
                .addr = ip_hdr.src,
                .port = @enumFromInt(try r.takeInt(u16, .big)),
            },
            .dst = .{
                .addr = ip_hdr.dst,
                .port = @enumFromInt(try r.takeInt(u16, .big)),
            },
            .seq = try r.takeInt(u32, .big),
            .ack = try r.takeInt(u32, .big),
            .off_4byte = @truncate(try r.takeInt(u8, .big) >> 4),
            .flg = @bitCast(try r.takeInt(u8, .big)),
            .wnd = try r.takeInt(u16, .big),
            .sum = try r.takeInt(u16, .big),
            .up = try r.takeInt(u16, .big),
        };

        const allocator = platform.allocator();
        while (r.seek < hdr.hlen()) {
            const opt: TcpOption = switch (try r.takeInt(u8, .big)) {
                0 => break,
                1 => .{ .no_operation = {} },
                2 => blk: {
                    const len = try r.takeInt(u8, .big);
                    if (len != 4) {
                        util.errorf(@src(), "invalid TCP option length: kind=2, len={d}", .{len});
                        return error.TcpOptionLengthError;
                    }
                    const mss = try r.takeInt(u16, .big);
                    break :blk .{ .maximum_segment_size = .{ .mss = mss } };
                },
                3 => blk: {
                    const len = try r.takeInt(u8, .big);
                    if (len != 3) {
                        util.errorf(@src(), "invalid TCP option length: kind=3, len={d}", .{len});
                        return error.TcpOptionLengthError;
                    }
                    _ = try r.take(1);
                    break :blk .{ .window_scale = {} };
                },
                4 => blk: {
                    const len = try r.takeInt(u8, .big);
                    if (len != 2) {
                        util.errorf(@src(), "invalid TCP option length: kind=4, len={d}", .{len});
                        return error.TcpOptionLengthError;
                    }
                    break :blk .{ .sack_permitted = {} };
                },
                5 => blk: {
                    const len = try r.takeInt(u8, .big);
                    if (len < 2) {
                        util.errorf(@src(), "invalid TCP option length: kind=5, len={d}", .{len});
                        return error.TcpOptionLengthError;
                    }
                    _ = try r.take(len - 2);
                    break :blk .{ .sack = {} };
                },
                8 => blk: {
                    const len = try r.takeInt(u8, .big);
                    if (len != 10) {
                        util.errorf(@src(), "invalid TCP option length: kind=8, len={d}", .{len});
                        return error.TcpOptionLengthError;
                    }
                    _ = try r.take(8);
                    break :blk .{ .timestamps = {} };
                },
                else => |kind| blk: {
                    const len = try r.takeInt(u8, .big);
                    _ = try r.take(len - 2);
                    break :blk .{ .unknown = .{ .kind = kind, .len = len } };
                },
            };
            try hdr.opts.append(allocator, opt);
        }

        const pseudo_hdr: udp.PseudoHdr = .{
            .src = ip_hdr.src,
            .dst = ip_hdr.dst,
            .proto = .tcp,
            .len = @intCast(data.len),
        };
        if (util.cksum16(data, pseudo_hdr.cksum16()) != 0) {
            util.errorf(@src(), "checksum error", .{});
            return error.TcpChecksumError;
        }

        return .{
            .hdr = hdr,
            .payload = data[hdr.hlen()..],
        };
    }

    pub fn encode(self: Self, w: *std.Io.Writer, data: []const u8) !void {
        const start = w.buffered().len;
        try w.writeInt(u16, @intFromEnum(self.src.port), .big);
        try w.writeInt(u16, @intFromEnum(self.dst.port), .big);
        try w.writeInt(u32, self.seq, .big);
        try w.writeInt(u32, self.ack, .big);
        try w.writeInt(u8, @as(u8, self.off_4byte) << 4, .big);
        try w.writeInt(u8, @as(u8, @bitCast(self.flg)), .big);
        try w.writeInt(u16, self.wnd, .big);
        try w.writeInt(u16, 0, .big);
        try w.writeInt(u16, self.up, .big);
        try w.writeAll(data);

        const msg_bytes = w.buffered()[start..];
        const pseudo_hdr: udp.PseudoHdr = .{
            .src = self.src.addr,
            .dst = self.dst.addr,
            .zero = 0,
            .proto = .tcp,
            .len = @intCast(self.hlen() + data.len),
        };
        const sum = util.cksum16(msg_bytes, pseudo_hdr.cksum16());
        std.mem.writeInt(u16, msg_bytes[16..18], sum, .big);
    }

    pub fn hlen(self: Self) u8 {
        return @as(u8, self.off_4byte) << 2;
    }

    pub fn format(
        self: @This(),
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        try writer.print("        src: {f}\n", .{self.src});
        try writer.print("        dst: {f}\n", .{self.dst});
        try writer.print("        seq: {d}\n", .{self.seq});
        try writer.print("        ack: {d}\n", .{self.ack});
        try writer.print("        off: 0x{x:0>2} ({d}) (options: {d})\n", .{ self.off_4byte, self.hlen(), self.hlen() - hdr_len_min });
        try writer.print("        flg: 0x{x:0>2} ({f})\n", .{ @as(u8, @bitCast(self.flg)), self.flg });
        try writer.print("        wnd: {d}\n", .{self.wnd});
        try writer.print("        sum: 0x{x:0>4}\n", .{self.sum});
        try writer.print("         up: {d}\n", .{self.up});
        for (self.opts.items, 0..) |opt, i| {
            const tag = std.meta.activeTag(opt);
            switch (opt) {
                .unknown => |o| {
                    try writer.print("     opt[{d}]: kind={d}, len={d}\n", .{ i, o.kind, o.len });
                },
                else => {
                    try writer.print("     opt[{d}]: kind={d} ({t})\n", .{ i, tag, tag });
                },
            }
        }
    }
};

const PcbTable = struct {
    const Self = @This();

    const size = 16;

    const Mode = enum {
        passive,
        active,
    };

    const State = enum {
        none,
        closed,
        listen,
        syn_sent,
        syn_received,
        established,
        fin_wait_1,
        fin_wait_2,
        close_wait,
        closing,
        last_ack,
        time_wait,
    };

    const SndVars = struct {
        // 次に送信するシーケンス番号
        nxt: u32 = 0,
        // 未確認の最小のシーケンス番号
        una: u32 = 0,
        // 受信側のウィンドウサイズ
        wnd: u16 = 0,
        // 緊急ポインタ
        up: u16 = 0,
        // 最後に受信したウィンドウ更新のシーケンス番号
        wl1: u32 = 0,
        // 最後に受信したウィンドウ更新の確認応答番号
        wl2: u32 = 0,
    };

    const RcvVars = struct {
        // 次に期待するシーケンス番号
        nxt: u32 = 0,
        // 受信側のウィンドウサイズ
        wnd: u16 = 0,
        // 緊急ポインタ
        up: u16 = 0,
    };

    const Pcb = struct {
        state: State = .none,
        local: udp.SocketAddr = .{},
        remote: udp.SocketAddr = .{},
        snd: SndVars = .{},
        // 初期送信シーケンス番号
        iss: u32 = 0,
        rcv: RcvVars = .{},
        // 初期受信シーケンス番号
        irs: u32 = 0,
        mss: u16 = 0,
        buf: [65535]u8 = undefined,
        task: sched.Task = .{},

        pub fn changeState(self: *Pcb, new_state: State) void {
            util.debugf(@src(), "{t} => {t}", .{ self.state, new_state });
            self.state = new_state;
        }
    };

    const SegInfo = struct {
        seq: u32,
        ack: u32,
        len: u16,
        wnd: u16,
        up: u16,
    };

    lock: platform.Lock = .{},
    pcbs: [size]Pcb = @splat(.{}),

    fn get(self: *Self, desc: usize) ?*Pcb {
        if (size <= desc) {
            return null;
        }
        const pcb = &self.pcbs[desc];
        return if (pcb.state != .none) pcb else null;
    }

    fn alloc(self: *Self) !usize {
        for (&self.pcbs, 0..) |*pcb, desc| {
            if (pcb.state == .none) {
                pcb.state = .closed;
                pcb.task = .{};
                return desc;
            }
        }
        return error.PcbTableFull;
    }

    fn release(_: *Self, pcb: *Pcb) void {
        pcb.task.destroy() catch |err| switch (err) {
            error.Busy => {
                util.debugf(@src(), "pending", .{});
                pcb.task.wakeup();
                return;
            },
        };
        pcb.* = .{};
        util.debugf(@src(), "success", .{});
    }

    fn select(self: *Self, local: udp.SocketAddr, remote: udp.SocketAddr) ?*Pcb {
        var candidate: ?*Pcb = null;
        for (&self.pcbs) |*pcb| {
            if (pcb.local.port != local.port) {
                continue;
            }
            if (!(pcb.local.addr.eql(local.addr) or pcb.local.addr.eql(ip.IpAddr.any)) and local.addr.eql(ip.IpAddr.any)) {
                continue;
            }

            const remote_matched = pcb.remote.addr.eql(remote.addr) and pcb.remote.port == remote.port;
            const pcb_remote_unspecified = pcb.remote.addr.eql(ip.IpAddr.any) and pcb.remote.port == udp.Port.unspecified;
            const key_remote_unspecified = remote.addr.eql(ip.IpAddr.any) and remote.port == udp.Port.unspecified;
            if (!remote_matched and !pcb_remote_unspecified and !key_remote_unspecified) {
                continue;
            }

            if (pcb.state != .listen) {
                return pcb;
            }
            candidate = pcb;
        }
        return candidate;
    }

    fn output(_: *Self, pcb: *Pcb, flg: TcpFlags, data: []const u8) !usize {
        const seq = if (flg.syn) pcb.iss else pcb.snd.nxt;
        if (flg.syn or flg.fin or data.len > 0) {
            // TODO: add retransmission queue
        }
        return outputSegment(seq, pcb.rcv.nxt, flg, pcb.rcv.wnd, data, pcb.local, pcb.remote);
    }

    pub fn open(self: *Self, local: udp.SocketAddr, remote: udp.SocketAddr, mode: Mode) !usize {
        self.lock.acquire();
        defer self.lock.release();

        const desc = self.alloc() catch |err| {
            util.errorf(@src(), "PcbTable.alloc() failure: {t}", .{err});
            return err;
        };
        const pcb = &self.pcbs[desc];

        util.debugf(@src(), "mode={t}, local={f}, remote={f}", .{ mode, local, remote });
        switch (mode) {
            .passive => {
                if (self.select(local, remote)) |_| {
                    util.errorf(@src(), "address already in use", .{});
                    self.release(pcb);
                    return error.PcbAlreadyInUse;
                }
                pcb.local = local;
                pcb.remote = remote;
                pcb.changeState(.listen);
                util.debugf(@src(), "waiting for connection...", .{});
            },
            .active => {
                // TODO
                util.errorf(@src(), "active open does not implement", .{});
                self.release(pcb);
                return error.TcpActiveOpenNotImplemented;
            },
        }

        const state = pcb.state;
        while (pcb.state == state or pcb.state == .syn_received) {
            pcb.task.sleep(&self.lock, null) catch {
                util.debugf(@src(), "interrupted", .{});
                pcb.changeState(.closed);
                self.release(pcb);
                return error.Interrupted;
            };
        }

        if (pcb.state != .established) {
            util.errorf(@src(), "open error: state={t}", .{pcb.state});
            pcb.changeState(.closed);
            self.release(pcb);
            return error.PcbOpenError;
        }

        const iface = ip.route.getIface(pcb.remote.addr) orelse {
            util.errorf(@src(), "iface not found", .{});
            return error.PcbIfaceNotFound;
        };
        pcb.mss = iface.dev().mtu - (ip.IpHdr.hdr_len_min + TcpHdr.hdr_len_min);
        util.debugf(@src(), "success, local={f}, remote={f}", .{ local, remote });
        return desc;
    }

    pub fn close(self: *Self, desc: usize) !void {
        self.lock.acquire();
        defer self.lock.release();

        const pcb = self.get(desc) orelse {
            util.errorf(@src(), "pcb not found: desc={d}", .{desc});
            return error.PcbNotFound;
        };
        util.debugf(@src(), "desc={d}", .{desc});
        _ = try self.output(pcb, .{ .rst = true }, &[_]u8{});
        pcb.changeState(.closed);
        self.release(pcb);
    }

    // rfc793 - section 3.9 [Event Processing > SEGMENT ARRIVES]
    pub fn segment_arrives(self: *Self, seg: SegInfo, flags: TcpFlags, _: []const u8, local: udp.SocketAddr, remote: udp.SocketAddr) !void {
        self.lock.acquire();
        defer self.lock.release();

        const pcb = blk: {
            if (self.select(local, remote)) |pcb| {
                if (pcb.state != .closed) {
                    break :blk pcb;
                }
                util.debugf(@src(), "PCB is closed", .{});
            } else {
                util.debugf(@src(), "PCB is not found", .{});
            }

            if (flags.rst) {
                return;
            }
            if (!flags.ack) {
                _ = try outputSegment(0, seg.seq + seg.len, .{ .rst = true, .ack = true }, 0, &[_]u8{}, local, remote);
            } else {
                _ = try outputSegment(seg.ack, 0, .{ .rst = true }, 0, &[_]u8{}, local, remote);
            }
            return;
        };

        util.debugf(@src(), "state={t}", .{pcb.state});
        switch (pcb.state) {
            .listen => {
                // 1st check for an RST
                if (flags.rst) {
                    return;
                }

                // 2nd check for an ACK
                if (flags.ack) {
                    _ = try outputSegment(seg.ack, 0, .{ .rst = true }, 0, &[_]u8{}, local, remote);
                    return;
                }

                // 3rd check for a SYN
                if (flags.syn) {
                    // ignore: security/compartment check
                    pcb.local = local;
                    pcb.remote = remote;
                    pcb.rcv.wnd = pcb.buf.len;
                    pcb.rcv.nxt = seg.seq + 1;
                    pcb.irs = seg.seq;
                    pcb.iss = platform.random32();
                    _ = try self.output(pcb, .{ .syn = true, .ack = true }, &[_]u8{});
                    pcb.snd.nxt = pcb.iss + 1;
                    pcb.snd.una = pcb.iss;
                    pcb.changeState(.syn_received);
                    // ignore: Note that any other incoming control or data (combined with SYN)
                    // will be processed in the SYN-RECEIVED state, but processing of SYN and ACK
                    // should not be repeated.
                    return;
                }

                // 4th other text or control
                // drop segment
            },
            .syn_sent => {
                // 1st check the ACK bit
                // 2nd check the RST bit
                // 3rd check security and precedence (ignore)
                // 4th check the SYN bit
                // 5th, if neither of the SYN or RST bits is set then drop the segment and return
                // drop segment
            },
            else => {
                // 1st check sequence number
                // 2nd check the RST bit
                // 3rd check security and precedence (ignore)
                // 4th check the SYN bit
                // 5th check the ACK field
                switch (pcb.state) {
                    .syn_received => {
                        if (pcb.snd.una <= seg.ack and seg.ack <= pcb.snd.nxt) {
                            pcb.changeState(.established);
                            pcb.task.wakeup();
                        } else {
                            _ = try outputSegment(seg.ack, 0, .{ .rst = true }, 0, &[_]u8{}, local, remote);
                            return;
                        }
                    },
                    else => {},
                }

                // 6th check the URG bit (ignore)
                // 7th process the segment text
                // 8th check the FIN bit
            },
        }
    }
};

var pcb_table: PcbTable = .{};

pub fn init() !void {
    ip.registerProtocol(.tcp, input) catch |err| {
        util.errorf(@src(), "ip.registerProtocol() failure: {t}", .{err});
        return err;
    };
}

fn input(ipd: *const ip.IpHdr.Decoded, data: []const u8, iface: *ip.IpIface) !void {
    const tcpd = try TcpHdr.decode(data, &ipd.hdr);

    const src_is_broadcast = tcpd.hdr.src.addr.eql(ip.IpAddr.broadcast) or tcpd.hdr.src.addr.eql(iface.broadcast);
    const dst_is_broadcast = tcpd.hdr.dst.addr.eql(ip.IpAddr.broadcast) or tcpd.hdr.dst.addr.eql(iface.broadcast);
    if (src_is_broadcast or dst_is_broadcast) {
        util.errorf(@src(), "only supports unicast, src={f}, dst={f}", .{ tcpd.hdr.src, tcpd.hdr.dst });
        return error.TcpUnicastOnly;
    }

    util.debugf(@src(), "{f} => {f}, len={d}, dev={s}", .{ tcpd.hdr.src, tcpd.hdr.dst, data.len, iface.dev().name() });
    util.dumpf("{f}", .{tcpd.hdr});
    util.debugdump(data);

    var seg = PcbTable.SegInfo{
        .seq = tcpd.hdr.seq,
        .ack = tcpd.hdr.ack,
        .len = @intCast(data.len - tcpd.hdr.hlen()),
        .wnd = tcpd.hdr.wnd,
        .up = tcpd.hdr.up,
    };
    if (tcpd.hdr.flg.syn) seg.len += 1;
    if (tcpd.hdr.flg.fin) seg.len += 1;
    try pcb_table.segment_arrives(seg, tcpd.hdr.flg, tcpd.payload, tcpd.hdr.dst, tcpd.hdr.src);
}

fn outputSegment(seq: u32, ack: u32, flg: TcpFlags, wnd: u16, data: []const u8, local: udp.SocketAddr, remote: udp.SocketAddr) !usize {
    var buf: [ip.payload_size_max]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const hdr = TcpHdr{
        .src = local,
        .dst = remote,
        .seq = seq,
        .ack = ack,
        .off_4byte = TcpHdr.hdr_len_min >> 2,
        .flg = flg,
        .wnd = wnd,
        .up = 0,
    };
    hdr.encode(&w, data) catch |err| {
        util.errorf(@src(), "TcpHdr.encode() failure: {t}", .{err});
        return err;
    };
    util.debugf(@src(), "{f} => {f}, len={d}", .{ local, remote, w.end });
    util.dumpf("{f}", .{hdr});
    util.debugdump(w.buffered());
    _ = ip.output(.tcp, w.buffered(), local.addr, remote.addr) catch |err| {
        util.errorf(@src(), "ip.output() failure: {t}", .{err});
        return err;
    };
    return data.len;
}

pub const cmd = struct {
    pub fn open(local: udp.SocketAddr, remote: udp.SocketAddr, mode: PcbTable.Mode) !usize {
        return pcb_table.open(local, remote, mode) catch |err| {
            util.errorf(@src(), "pcb_table.open() failure: {t}", .{err});
            return err;
        };
    }

    pub fn close(desc: usize) !void {
        return pcb_table.close(desc) catch |err| {
            util.errorf(@src(), "pcb_table.close() failure: {t}", .{err});
            return err;
        };
    }
};
