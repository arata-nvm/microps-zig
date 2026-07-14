const std = @import("std");

const ip = @import("ip.zig");
const platform = @import("platform.zig");
const udp = @import("udp.zig");
const util = @import("util.zig");

const sched = platform.sched;
const timer = platform.timer;

const TcpFlags = packed struct(u8) {
    const Self = @This();

    fin: bool = false,
    syn: bool = false,
    rst: bool = false,
    psh: bool = false,
    ack: bool = false,
    urg: bool = false,
    zero: u2 = 0,

    pub fn seqLen(self: Self) u32 {
        return @intFromBool(self.syn) + @intFromBool(self.fin);
    }

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

    pub fn deinit(self: *Self) void {
        const allocator = platform.allocator();
        self.opts.deinit(allocator);
    }

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
                    if (len < 2) {
                        return error.TcpInvalidLen;
                    }
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

        if (hdr.hlen() > data.len) {
            return error.TcpInvalidLen;
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

pub const Mode = enum {
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
    const Self = @This();

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
    // 初期送信シーケンス番号
    iss: u32 = 0,

    fn init(iss: u32) Self {
        return .{ .iss = iss, .una = iss, .nxt = iss };
    }

    fn ackAcceptable(self: Self, ack: u32) bool {
        return self.una <= ack and ack <= self.nxt;
    }

    fn ackAdvances(self: Self, ack: u32) bool {
        return self.una < ack and ack <= self.nxt;
    }

    fn ackIsFuture(self: Self, ack: u32) bool {
        return self.nxt < ack;
    }

    fn shouldUpdateWindow(self: Self, seg: SegInfo) bool {
        return self.wl1 < seg.seq or (self.wl1 == seg.seq and self.wl2 <= seg.ack);
    }

    fn updateWindow(self: *Self, seg: SegInfo) void {
        self.wnd = seg.wnd;
        self.wl1 = seg.seq;
        self.wl2 = seg.ack;
    }

    fn inFlight(self: Self) u32 {
        return self.nxt -% self.una;
    }

    fn usableWindow(self: Self) u32 {
        return self.wnd -% self.inFlight();
    }
};

const RcvVars = struct {
    const Self = @This();

    // 次に期待するシーケンス番号
    nxt: u32 = 0,
    // 受信側のウィンドウサイズ
    wnd: u16 = 0,
    // 緊急ポインタ
    up: u16 = 0,
    // 初期受信シーケンス番号
    irs: u32 = 0,

    fn inWindow(self: Self, seq: u32) bool {
        return self.nxt <= seq and seq < self.nxt +% self.wnd;
    }

    fn accepts(self: Self, seg: SegInfo) bool {
        if (seg.len == 0) {
            if (self.wnd == 0) {
                return seg.seq == self.nxt;
            } else {
                return self.inWindow(seg.seq);
            }
        } else {
            if (self.wnd == 0) {
                return false;
            } else {
                return self.inWindow(seg.seq) or self.inWindow(seg.seq +% seg.len -% 1);
            }
        }
    }

    fn acceptSyn(self: *Self, seq: u32) void {
        self.irs = seq;
        self.nxt = seq +% 1;
    }
};

const SegInfo = struct {
    const Self = @This();

    seq: u32,
    ack: u32,
    len: u16,
    wnd: u16,
    up: u16,
    flg: TcpFlags,

    pub fn init(d: TcpHdr.Decoded) Self {
        const len: u16 = @intCast(d.payload.len + d.hdr.flg.seqLen());
        return Self{
            .seq = d.hdr.seq,
            .ack = d.hdr.ack,
            .len = len,
            .wnd = d.hdr.wnd,
            .up = d.hdr.up,
            .flg = d.hdr.flg,
        };
    }
};

const retrans_timeout: std.Io.Duration = .fromMilliseconds(200);
const retrans_deadline: std.Io.Duration = .fromSeconds(12);

const QueueEntry = struct {
    const Self = @This();

    first: std.Io.Timestamp,
    last: std.Io.Timestamp,
    rto: std.Io.Duration = retrans_timeout,
    seq: u32,
    flg: TcpFlags,
    len: u32,
    data: []const u8,

    fn fullyAckedBy(self: Self, una: u32) bool {
        return self.seq +% self.len <= una;
    }

    fn deadlineExceeded(self: Self, now: std.Io.Timestamp) bool {
        const deadline = self.first.addDuration(retrans_deadline);
        return deadline.nanoseconds < now.nanoseconds;
    }

    fn shouldRetransmit(self: Self, now: std.Io.Timestamp) bool {
        const timeout = self.last.addDuration(self.rto);
        return timeout.nanoseconds < now.nanoseconds;
    }

    fn backoff(self: *Self, now: std.Io.Timestamp) void {
        self.last = now;
        self.rto.nanoseconds *= 2;
    }
};

const timewait: std.Io.Duration = .fromSeconds(30);

const Pcb = struct {
    state: State = .none,
    mode: PcbMode = .rfc793,
    local: udp.SocketAddr = .{},
    remote: udp.SocketAddr = .{},
    snd: SndVars = .{},
    rcv: RcvVars = .{},
    mss: u16 = 0,
    buf: [65535]u8 = undefined,
    task: sched.Task = .{},
    queue: util.Queue(QueueEntry) = .{},
    tw_timer: std.Io.Timestamp = .zero,
    parent: ?*Pcb = null,
    backlog: util.Queue(*Pcb) = .{},
    backlog_max: usize = 0,

    const PcbMode = enum {
        rfc793,
        socket,
    };

    fn changeState(self: *Pcb, new_state: State) void {
        util.debugf(@src(), "{t} => {t}", .{ self.state, new_state });
        self.state = new_state;
    }

    fn setTimewaitTimer(self: *Pcb) void {
        const now = platform.now();
        self.tw_timer = now.addDuration(timewait);
        util.debugf(@src(), "start time_wait timer: {d} seconds", .{timewait.toSeconds()});
    }

    fn timewaitElapsed(self: *Pcb, now: std.Io.Timestamp) bool {
        return self.tw_timer.nanoseconds < now.nanoseconds;
    }

    fn processAck(self: *Pcb, seg: SegInfo) void {
        self.snd.una = seg.ack;
        self.cleanupRetransQueue();
        // ignore: Users should receive positive acknowledgments for buffers
        //         which have been SENT and fully acknowledged
        //         (i.e., SEND buffer should be returned with "ok" response)
        if (self.snd.shouldUpdateWindow(seg)) {
            self.snd.updateWindow(seg);
        }
    }

    fn storeBuf(self: *Pcb, seg: SegInfo, data: []const u8) void {
        const offset = self.buf.len - self.rcv.wnd;
        @memcpy(self.buf[offset .. offset + data.len], data);
        self.rcv.nxt = seg.seq +% @as(u32, @intCast(data.len));
        self.rcv.wnd -= @intCast(data.len);
    }

    fn availableBuf(self: *const Pcb) usize {
        return self.buf.len - self.rcv.wnd;
    }

    fn readBuf(self: *Pcb, buf: []u8) usize {
        const remain = self.availableBuf();
        const len = @min(buf.len, remain);
        @memcpy(buf[0..len], self.buf[0..len]);
        @memmove(self.buf[0 .. remain - len], self.buf[len..remain]);
        self.rcv.wnd += @intCast(len);
        return len;
    }

    fn release(self: *Pcb) void {
        self.task.destroy() catch |err| switch (err) {
            error.Busy => {
                util.debugf(@src(), "pending", .{});
                self.task.wakeup();
                return;
            },
        };

        const allocator = platform.allocator();
        while (self.queue.pop()) |entry| {
            util.debugf(@src(), "free queue entry", .{});
            allocator.free(entry.data);
        }

        while (self.backlog.pop()) |b| {
            util.debugf(@src(), "release backlog entry, state={t}", .{b.state});
            if (b.state != .closed) {
                _ = b.output(.{ .rst = true }, &[_]u8{}) catch {};
                b.changeState(.closed);
            }
            b.release();
        }

        self.* = .{};
        util.debugf(@src(), "success", .{});
    }

    fn addRetransQueue(self: *Pcb, seq: u32, flg: TcpFlags, data: []const u8, len: u32) !void {
        const allocator = platform.allocator();
        const ptr = try allocator.dupe(u8, data);
        errdefer allocator.free(ptr);

        const now = platform.now();
        const entry: QueueEntry = .{
            .first = now,
            .last = now,
            .seq = seq,
            .flg = flg,
            .len = len,
            .data = ptr,
        };
        self.queue.push(entry) catch |err| {
            util.errorf(@src(), "self.queue.push() failure: {t}", .{err});
            return err;
        };
        util.debugf(@src(), "num={d}, seq={d}", .{ self.queue.num, entry.seq });
    }

    fn cleanupRetransQueue(self: *Pcb) void {
        const allocator = platform.allocator();
        while (self.queue.peek()) |entry| {
            if (!entry.fullyAckedBy(self.snd.una)) {
                break;
            }
            _ = self.queue.pop();
            util.debugf(@src(), "num={d}, seq={d}", .{ self.queue.num, entry.seq });
            allocator.free(entry.data);
        }
    }

    fn emitRetrans(self: *Pcb) !void {
        const now = platform.now();
        var iter = self.queue.iterator();
        while (iter.next()) |entry| {
            if (entry.deadlineExceeded(now)) {
                self.changeState(.closed);
                self.task.wakeup();
                return;
            }
            if (entry.shouldRetransmit(now)) {
                util.debugf(@src(), "seq={d}", .{entry.seq});
                _ = try outputSegment(entry.seq, self.rcv.nxt, entry.flg, self.rcv.wnd, entry.data, self.local, self.remote);
                entry.backoff(now);
            }
        }
    }

    fn startActiveOpen(self: *Pcb, local: udp.SocketAddr, remote: udp.SocketAddr) !void {
        self.local = local;
        self.remote = remote;
        self.rcv.wnd = self.buf.len;
        self.snd = .init(platform.random32());
        _ = try self.output(.{ .syn = true }, &[_]u8{});
        self.changeState(.syn_sent);
    }

    fn waitEstablished(self: *Pcb, lock: *platform.Lock) !void {
        const initial = self.state;
        while (self.state == initial or self.state == .syn_received) {
            self.task.sleep(lock, null) catch return error.Interrupted;
        }
        if (self.state != .established) return error.PcbOpenError;
    }

    fn updateMss(self: *Pcb) !void {
        const iface = ip.route.getIface(self.remote.addr) orelse return error.PcbIfaceNotFound;
        self.mss = iface.dev().mtu - (ip.IpHdr.hdr_len_min + TcpHdr.hdr_len_min);
    }

    fn output(self: *Pcb, flg: TcpFlags, data: []const u8) !usize {
        const seq = if (flg.syn) self.snd.iss else self.snd.nxt;
        const len: u32 = @as(u32, @intCast(data.len)) + flg.seqLen();
        if (len > 0) {
            try self.addRetransQueue(seq, flg, data, len);
        }
        const n = outputSegment(seq, self.rcv.nxt, flg, self.rcv.wnd, data, self.local, self.remote);
        self.snd.nxt = seq +% len;
        return n;
    }

    fn arrivesListen(self: *Pcb, seg: SegInfo, local: udp.SocketAddr, remote: udp.SocketAddr) !void {
        // 1st check for an RST
        if (seg.flg.rst) {
            return;
        }

        // 2nd check for an ACK
        if (seg.flg.ack) {
            try replyRst(seg, local, remote);
            return;
        }

        // 3rd check for a SYN
        if (seg.flg.syn) {
            // ignore: security/compartment check
            var pcb = self;
            if (self.mode == .socket) {
                if (self.backlog_max < self.backlog.num) {
                    util.warnf(@src(), "backlog is full", .{});
                    return;
                }
                const new_desc = pcb_table.alloc() catch |err| {
                    util.errorf(@src(), "pcb_table.alloc() failure: {t}", .{err});
                    return err;
                };
                const new_pcb = &pcb_table.pcbs[new_desc];
                util.debugf(@src(), "allocate PCB for new connection, desc={d}, state={t}", .{ new_desc, new_pcb.state });
                new_pcb.parent = self;
                pcb = new_pcb;
            }

            pcb.local = local;
            pcb.remote = remote;
            pcb.rcv.wnd = pcb.buf.len;
            pcb.rcv.acceptSyn(seg.seq);
            pcb.snd = .init(platform.random32());
            _ = try pcb.output(.{ .syn = true, .ack = true }, &[_]u8{});
            pcb.changeState(.syn_received);
            // ignore: Note that any other incoming control or data (combined with SYN)
            // will be processed in the SYN-RECEIVED state, but processing of SYN and ACK
            // should not be repeated.
            return;
        }

        // 4th other text or control
        // drop segment
    }

    fn arrivesSynSent(self: *Pcb, seg: SegInfo, local: udp.SocketAddr, remote: udp.SocketAddr) !void {
        var acceptable: bool = false;

        // 1st check the ACK bit
        if (seg.flg.ack) {
            if (seg.ack <= self.snd.iss or seg.ack > self.snd.nxt) {
                _ = try outputSegment(seg.ack, 0, .{ .rst = true }, 0, &[_]u8{}, local, remote);
                return;
            }
            acceptable = self.snd.ackAcceptable(seg.ack);
        }

        // 2nd check the RST bit
        if (seg.flg.rst) {
            if (acceptable) {
                util.errorf(@src(), "connection reset", .{});
                self.changeState(.closed);
                self.release();
            }
            // drop segment
            return;
        }

        // 3rd check security and precedence (ignore)
        // 4th check the SYN bit
        if (seg.flg.syn) {
            self.rcv.acceptSyn(seg.seq);
            if (acceptable) {
                self.snd.una = seg.ack;
                self.cleanupRetransQueue();
            }
            if (self.snd.una > self.snd.iss) {
                self.changeState(.established);
                _ = try self.output(.{ .ack = true }, &[_]u8{});
                // NOTE: not specified in the RFC793, but send window initialization required
                self.snd.updateWindow(seg);
                self.task.wakeup();
                // ignore: continue processing at the sixth step below where the URG bit is checked
                return;
            } else {
                // simultaneous open
                self.changeState(.syn_received);
                _ = try self.output(.{ .syn = true, .ack = true }, &[_]u8{});
                // ignore: If there are other controls or text in the segment,
                //         queue them for processing after the ESTABLISHED state has been reached
                return;
            }
        }

        // 5th, if neither of the SYN or RST bits is set then drop the segment and return
        // drop segment
    }

    fn arrivesOtherwise(self: *Pcb, seg: SegInfo, data: []const u8, local: udp.SocketAddr, remote: udp.SocketAddr) !void {
        // 1st check sequence number
        const acceptable = switch (self.state) {
            .syn_received, .established, .fin_wait_1, .fin_wait_2, .close_wait, .closing, .last_ack, .time_wait => self.rcv.accepts(seg),
            else => false,
        };
        if (!acceptable) {
            if (!seg.flg.rst) {
                _ = try self.output(.{ .ack = true }, &[_]u8{});
            }
            return;
        }
        // In the following it is assumed that the segment is the idealized
        // segment that begins at RCV.NXT and does not exceed the window.
        // One could tailor actual segments to fit this assumption by
        // trimming off any portions that lie outside the window (including
        // SYN and FIN), and only processing further if the segment then
        // begins at RCV.NXT.  Segments with higher begining sequence
        // numbers may be held for later processing.

        // 2nd check the RST bit
        switch (self.state) {
            .syn_received => {
                if (seg.flg.rst) {
                    self.changeState(.closed);
                    self.release();
                    return;
                }
            },
            .established, .fin_wait_1, .fin_wait_2, .close_wait => {
                if (seg.flg.rst) {
                    util.errorf(@src(), "connection reset", .{});
                    self.changeState(.closed);
                    self.release();
                    return;
                }
            },
            .closing, .last_ack, .time_wait => {
                if (seg.flg.rst) {
                    self.changeState(.closed);
                    self.release();
                    return;
                }
            },
            else => {},
        }

        // 3rd check security and precedence (ignore)
        // 4th check the SYN bit
        switch (self.state) {
            .syn_received, .established, .fin_wait_1, .fin_wait_2, .close_wait, .closing, .last_ack, .time_wait => {
                if (seg.flg.syn) {
                    _ = try self.output(.{ .rst = true }, &[_]u8{});
                    util.errorf(@src(), "connection reset", .{});
                    self.changeState(.closed);
                    self.release();
                    return;
                }
            },
            else => {},
        }

        // 5th check the ACK field
        if (!seg.flg.ack) {
            // drop segment
            return;
        }
        switch (self.state) {
            .syn_received => {
                if (self.snd.ackAcceptable(seg.ack)) {
                    self.changeState(.established);
                    self.task.wakeup();
                    if (self.parent) |parent| {
                        try parent.backlog.push(self);
                        parent.task.wakeup();
                    }
                } else {
                    try replyRst(seg, local, remote);
                    return;
                }
            },
            else => {},
        }
        switch (self.state) {
            .established, .fin_wait_1, .fin_wait_2, .close_wait, .closing => {
                if (self.snd.ackAdvances(seg.ack)) {
                    self.processAck(seg);
                } else if (seg.ack < self.snd.una) {
                    // ignore
                } else if (self.snd.ackIsFuture(seg.ack)) {
                    _ = try self.output(.{ .ack = true }, &[_]u8{});
                    return;
                }
                switch (self.state) {
                    .fin_wait_1 => {
                        if (seg.ack == self.snd.nxt) {
                            self.changeState(.fin_wait_2);
                        }
                    },
                    .fin_wait_2 => {
                        // do not delete the PCB
                    },
                    .close_wait => {
                        // do nothing
                    },
                    .closing => {
                        if (seg.ack == self.snd.nxt) {
                            self.changeState(.time_wait);
                            // NOTE: set 2MSL timer, although it is not explicitly stated in the RFC
                            self.setTimewaitTimer();
                            self.task.wakeup();
                        }
                    },
                    else => {},
                }
            },
            .last_ack => {
                if (seg.ack == self.snd.nxt) {
                    self.changeState(.closed);
                    self.release();
                }
                return;
            },
            .time_wait => {
                if (seg.flg.fin) {
                    self.setTimewaitTimer();
                }
            },
            else => {},
        }

        // 6th check the URG bit (ignore)
        // 7th process the segment text
        switch (self.state) {
            .established, .fin_wait_1, .fin_wait_2 => {
                if (data.len > 0) {
                    if (self.rcv.nxt != seg.seq or self.rcv.wnd < data.len) {
                        // NOTE: Request the optimal segment
                        _ = try self.output(.{ .ack = true }, &[_]u8{});
                        return;
                    }
                    util.debugf(@src(), "copy segment text, len={d}, wnd={d}", .{ data.len, self.rcv.wnd });
                    self.storeBuf(seg, data);
                    _ = try self.output(.{ .ack = true }, &[_]u8{});
                    self.task.wakeup();
                }
            },
            .close_wait, .closing, .last_ack, .time_wait => {
                // ignore segment text
            },
            else => {},
        }

        // 8th check the FIN bit
        if (seg.flg.fin) {
            if (self.state == .closed or self.state == .listen) {
                // drop segment
                return;
            }
            self.rcv.nxt = seg.seq +% 1;
            _ = try self.output(.{ .ack = true }, &[_]u8{});
            switch (self.state) {
                .syn_received, .established => {
                    self.changeState(.close_wait);
                    self.task.wakeup();
                },
                .fin_wait_1 => {
                    if (seg.ack == self.snd.nxt) {
                        self.changeState(.time_wait);
                        self.setTimewaitTimer();
                    } else {
                        self.changeState(.closing);
                    }
                },
                .fin_wait_2 => {
                    self.changeState(.time_wait);
                    self.setTimewaitTimer();
                },
                .close_wait => {
                    // Remain in the CLOSE-WAIT state
                },
                .closing => {
                    // Remain in the CLOSING state
                },
                .last_ack => {
                    // Remain in the LAST-ACK state
                },
                .time_wait => {
                    // Remain in the TIME-WAIT state
                },
                else => {},
            }
        }
    }
};

const PcbTable = struct {
    const Self = @This();

    const size = 16;
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

    fn select(self: *Self, local: udp.SocketAddr, remote: udp.SocketAddr) ?*Pcb {
        var candidate: ?*Pcb = null;
        for (&self.pcbs) |*pcb| {
            if (pcb.local.port != local.port) {
                continue;
            }
            if (!(pcb.local.addr.eql(local.addr) or pcb.local.addr.eql(.any)) and local.addr.eql(ip.IpAddr.any)) {
                continue;
            }

            const remote_matched = pcb.remote.addr.eql(remote.addr) and pcb.remote.port == remote.port;
            const pcb_remote_unspecified = pcb.remote.addr.eql(.any) and pcb.remote.port == udp.Port.unspecified;
            const key_remote_unspecified = remote.addr.eql(.any) and remote.port == udp.Port.unspecified;
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

    pub fn open(self: *Self, local: udp.SocketAddr, remote: udp.SocketAddr, mode: Mode) !usize {
        self.lock.acquire();
        defer self.lock.release();

        const desc = self.alloc() catch |err| {
            util.errorf(@src(), "PcbTable.alloc() failure: {t}", .{err});
            return err;
        };
        const pcb = &self.pcbs[desc];
        errdefer {
            pcb.changeState(.closed);
            pcb.release();
        }

        util.debugf(@src(), "mode={t}, local={f}, remote={f}", .{ mode, local, remote });
        switch (mode) {
            .passive => {
                if (self.select(local, remote)) |_| {
                    util.errorf(@src(), "address already in use", .{});
                    return error.PcbAlreadyInUse;
                }
                pcb.local = local;
                pcb.remote = remote;
                pcb.changeState(.listen);
                util.debugf(@src(), "waiting for connection...", .{});
            },
            .active => {
                const resolved_local = try self.resolveLocal(local, remote);
                if (self.select(resolved_local, remote)) {
                    util.errorf(@src(), "address already in use", .{});
                    return error.TcpAlreadyInUse;
                }
                util.debugf(@src(), "resolve local address, addr={f}", .{resolved_local});
                pcb.startActiveOpen(resolved_local, remote) catch |err| {
                    util.errorf(@src(), "pcb.startActiveOpen() failure: {t}", .{err});
                    return err;
                };
            },
        }

        pcb.waitEstablished(&self.lock) catch |err| {
            util.errorf(@src(), "pcb.waitEstablished() failure: {t}", .{err});
            return err;
        };
        pcb.updateMss() catch |err| {
            util.errorf(@src(), "pcb.updateMss() failure: {t}", .{err});
            return err;
        };

        util.debugf(@src(), "success, local={f}, remote={f}", .{ local, remote });
        return desc;
    }

    pub fn socket(self: *Self) !usize {
        self.lock.acquire();
        defer self.lock.release();

        const desc = self.alloc() catch |err| {
            util.errorf(@src(), "PcbTable.alloc() failure: {t}", .{err});
            return err;
        };
        const pcb = &self.pcbs[desc];

        pcb.mode = .socket;
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

        switch (pcb.state) {
            .closed => {
                util.errorf(@src(), "connection does not exist", .{});
                return error.PcbConnectionDoesNotExist;
            },
            .listen, .syn_sent => {
                pcb.changeState(.closed);
            },
            .syn_received, .established => {
                util.debugf(@src(), "close connection", .{});
                _ = try pcb.output(.{ .ack = true, .fin = true }, &[_]u8{});
                pcb.changeState(.fin_wait_1);
            },
            .close_wait => {
                util.debugf(@src(), "close connection", .{});
                _ = try pcb.output(.{ .ack = true, .fin = true }, &[_]u8{});
                pcb.changeState(.last_ack);
            },
            .fin_wait_1, .fin_wait_2, .closing, .last_ack, .time_wait => {
                util.errorf(@src(), "connection closing", .{});
                return error.PcbConnectionClosing;
            },
            else => {
                util.errorf(@src(), "unknown state: {t}", .{pcb.state});
                return error.PcbUnknownState;
            },
        }

        if (pcb.state == .closed) {
            pcb.release();
        } else {
            pcb.task.wakeup();
        }
    }

    pub fn connect(self: *Self, desc: usize, remote: udp.SocketAddr) !void {
        self.lock.acquire();
        defer self.lock.release();

        const pcb = self.get(desc) orelse {
            util.errorf(@src(), "pcb not found: desc={d}", .{desc});
            return error.PcbNotFound;
        };
        errdefer {
            pcb.changeState(.closed);
            pcb.release();
        }

        util.debugf(@src(), "local={f}, remote={f}", .{ pcb.local, remote });

        const resolved_local = try self.resolveLocal(pcb.local, remote);
        if (self.select(resolved_local, remote)) |_| {
            util.errorf(@src(), "address already in use", .{});
            return error.TcpAlreadyInUse;
        }

        pcb.startActiveOpen(resolved_local, remote) catch |err| {
            util.errorf(@src(), "pcb.startActiveOpen() failure: {t}", .{err});
            return err;
        };
        pcb.waitEstablished(&self.lock) catch |err| {
            util.errorf(@src(), "pcb.waitEstablished() failure: {t}", .{err});
            return err;
        };
        pcb.updateMss() catch |err| {
            util.errorf(@src(), "pcb.updateMss() failure: {t}", .{err});
            return err;
        };

        util.debugf(@src(), "success, local={f}, remote={f}", .{ pcb.local, pcb.remote });
    }

    pub fn bind(self: *Self, desc: usize, local: udp.SocketAddr) !void {
        self.lock.acquire();
        defer self.lock.release();

        const pcb = self.get(desc) orelse {
            util.errorf(@src(), "pcb not found: desc={d}", .{desc});
            return error.PcbNotFound;
        };

        if (local.port == udp.Port.unspecified) {
            util.errorf(@src(), "invalid port", .{});
            return error.PcbInvalidPort;
        }
        if (pcb.state != .closed) {
            util.errorf(@src(), "pcb is not CLOSED state", .{});
            return error.PcbNotClosedState;
        }
        if (self.select(local, udp.SocketAddr.any)) |e| {
            util.errorf(@src(), "already bound, exist={f}", .{e.local});
            return error.PcbAlreadyBound;
        }
        pcb.local = local;
        util.debugf(@src(), "success, local={f}", .{pcb.local});
    }

    pub fn listen(self: *Self, desc: usize, backlog: usize) !void {
        self.lock.acquire();
        defer self.lock.release();

        const pcb = self.get(desc) orelse {
            util.errorf(@src(), "pcb not found: desc={d}", .{desc});
            return error.PcbNotFound;
        };

        if (pcb.local.port == udp.Port.unspecified) {
            util.errorf(@src(), "pcb is not bound", .{});
            return error.PcbNotBound;
        }
        if (pcb.state != .closed) {
            util.errorf(@src(), "pcb is not CLOSED state", .{});
            return error.NotClosedState;
        }
        pcb.backlog_max = backlog;
        pcb.changeState(.listen);
    }

    pub fn accept(self: *Self, desc: usize) !AcceptResult {
        self.lock.acquire();
        defer self.lock.release();

        const pcb = self.get(desc) orelse {
            util.errorf(@src(), "pcb not found: desc={d}", .{desc});
            return error.NotFound;
        };

        if (pcb.state != .listen) {
            util.errorf(@src(), "not in LISTEN state", .{});
            return error.NotListenState;
        }
        while (true) {
            const new_pcb = pcb.backlog.pop() orelse {
                pcb.task.sleep(&self.lock, null) catch |err| {
                    util.debugf(@src(), "interrupted", .{});
                    return err;
                };
                if (pcb.state == .closed) {
                    util.debugf(@src(), "closed", .{});
                    pcb.release();
                    return error.Closed;
                }
                continue;
            };

            const remote = new_pcb.remote;
            const iface = ip.route.getIface(remote.addr) orelse {
                util.errorf(@src(), "iface not found that can reach foreign address, addr={f}", .{remote.addr});
                return error.PcbNoRoute;
            };
            new_pcb.mss = iface.dev().mtu - (ip.IpHdr.hdr_len_min + TcpHdr.hdr_len_min);
            const new_desc = @divExact(@intFromPtr(new_pcb) - @intFromPtr(&pcb_table.pcbs[0]), @sizeOf(Pcb));
            util.debugf(@src(), "success, desc={d}, local={f}, remote={f}", .{ new_desc, new_pcb.local, new_pcb.remote });
            return .{
                .desc = new_desc,
                .remote = remote,
            };
        }
    }

    pub fn send(self: *Self, desc: usize, data: []const u8) !usize {
        self.lock.acquire();
        defer self.lock.release();

        const pcb = self.get(desc) orelse {
            util.errorf(@src(), "pcb not found: desc={d}", .{desc});
            return error.PcbNotFound;
        };

        var sent: usize = 0;
        while (true) {
            switch (pcb.state) {
                .fin_wait_1, .fin_wait_2, .closing, .last_ack, .time_wait => {
                    util.errorf(@src(), "connection closing", .{});
                    return error.PcbConnectionClosing;
                },
                .established, .close_wait => {},
                else => {
                    util.errorf(@src(), "invalid state: {t}", .{pcb.state});
                    return error.PcbInvalidState;
                },
            }

            blk: {
                while (sent < data.len) {
                    const cap = pcb.snd.usableWindow();
                    if (cap == 0) {
                        pcb.task.sleep(&self.lock, null) catch {
                            util.debugf(@src(), "interrupted", .{});
                            if (sent == 0) {
                                return error.Interrupted;
                            }
                            return sent;
                        };
                        break :blk; // retry
                    }
                    const slen = @min(pcb.mss, data.len - sent, cap);
                    _ = pcb.output(.{ .ack = true, .psh = true }, data[sent .. sent + slen]) catch |err| {
                        util.errorf(@src(), "pcb.output() failure: {t}", .{err});
                        pcb.changeState(.closed);
                        pcb.release();
                        return error.PcbOutputFailure;
                    };
                    sent += slen;
                }
                return sent;
            }
        }
    }

    pub fn receive(self: *Self, desc: usize, buf: []u8) !usize {
        self.lock.acquire();
        defer self.lock.release();

        const pcb = self.get(desc) orelse {
            util.errorf(@src(), "pcb not found: desc={d}", .{desc});
            return error.PcbNotFound;
        };

        while (true) {
            switch (pcb.state) {
                .closing, .last_ack, .time_wait => {
                    util.debugf(@src(), "connection closing", .{});
                    return 0;
                },
                .close_wait => {
                    if (pcb.availableBuf() == 0) {
                        util.debugf(@src(), "connection closing", .{});
                        return 0;
                    }
                },
                .established, .fin_wait_1, .fin_wait_2 => {},
                else => {
                    util.errorf(@src(), "invalid state: {t}", .{pcb.state});
                    return error.PcbInvalidState;
                },
            }

            if (pcb.availableBuf() == 0) {
                pcb.task.sleep(&self.lock, null) catch {
                    util.debugf(@src(), "interrupted", .{});
                    return error.Interrupted;
                };
                continue;
            }

            return pcb.readBuf(buf);
        }
    }

    // rfc793 - section 3.9 [Event Processing > SEGMENT ARRIVES]
    pub fn segmentArrives(self: *Self, seg: SegInfo, data: []const u8, local: udp.SocketAddr, remote: udp.SocketAddr) !void {
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

            if (seg.flg.rst) {
                return;
            }
            try replyRst(seg, local, remote);
            return;
        };

        util.debugf(@src(), "state={t}", .{pcb.state});
        switch (pcb.state) {
            .listen => try pcb.arrivesListen(seg, local, remote),
            .syn_sent => try pcb.arrivesSynSent(seg, local, remote),
            else => try pcb.arrivesOtherwise(seg, data, local, remote),
        }
    }

    pub fn timer(self: *Self) void {
        self.lock.acquire();
        defer self.lock.release();

        const now = platform.now();
        for (&self.pcbs, 0..) |*pcb, desc| {
            if (pcb.state == .none) {
                continue;
            }
            if (pcb.state == .time_wait and pcb.timewaitElapsed(now)) {
                util.debugf(@src(), "timewait has elapsed, desc={d}", .{desc});
                pcb.changeState(.closed);
                pcb.release();
                continue;
            }
            pcb.emitRetrans() catch |err| {
                util.errorf(@src(), "pcb.emitRetrans() failure: {t}", .{err});
            };
        }
    }

    fn resolveLocal(self: *Self, local: udp.SocketAddr, remote: udp.SocketAddr) !udp.SocketAddr {
        var resolved = local;
        if (local.addr.eql(.any)) {
            const iface = ip.route.getIface(remote.addr) orelse {
                util.errorf(@src(), "iface not found that can reach foreign address, addr={f}", .{remote.addr});
                return error.PcbNoRoute;
            };
            resolved.addr = iface.unicast;
        }
        if (local.port == udp.Port.unspecified) {
            resolved.port = try self.allocPort(local, remote);
        }
        return resolved;
    }

    fn allocPort(self: *Self, local: udp.SocketAddr, remote: udp.SocketAddr) !udp.Port {
        const min: u32 = @intFromEnum(udp.Port.dynamic_min);
        const max: u32 = @intFromEnum(udp.Port.dynamic_max);
        var key = local;
        for (min..max + 1) |p| {
            const port: udp.Port = @enumFromInt(p);
            key.port = port;
            if (self.select(key, remote) == null) {
                util.debugf(@src(), "dynamic assign local port, port={d}", .{port});
                return port;
            }
        }

        util.debugf(@src(), "failed to dynamic assign local port, addr={f}", .{local.addr});
        return error.PcbNoAvailablePort;
    }
};

var pcb_table: PcbTable = .{};

pub const AcceptResult = struct {
    desc: usize,
    remote: udp.SocketAddr,
};

pub fn init() !void {
    ip.registerProtocol(.tcp, input) catch |err| {
        util.errorf(@src(), "ip.registerProtocol() failure: {t}", .{err});
        return err;
    };
    timer.register(.fromMilliseconds(100), timerHandler) catch |err| {
        util.errorf(@src(), "timer.register() failure: {t}", .{err});
        return err;
    };
}

fn input(ipd: *const ip.IpHdr.Decoded, data: []const u8, iface: *ip.IpIface) void {
    var tcpd = TcpHdr.decode(data, &ipd.hdr) catch |err| {
        util.errorf(@src(), "TcpHdr.decode() failure: {t}", .{err});
        return;
    };
    defer tcpd.hdr.deinit();

    const src_is_broadcast = tcpd.hdr.src.addr.eql(.broadcast) or tcpd.hdr.src.addr.eql(iface.broadcast);
    const dst_is_broadcast = tcpd.hdr.dst.addr.eql(.broadcast) or tcpd.hdr.dst.addr.eql(iface.broadcast);
    if (src_is_broadcast or dst_is_broadcast) {
        util.errorf(@src(), "only supports unicast, src={f}, dst={f}", .{ tcpd.hdr.src, tcpd.hdr.dst });
        return;
    }

    util.debugf(@src(), "{f} => {f}, len={d}, dev={s}", .{ tcpd.hdr.src, tcpd.hdr.dst, data.len, iface.dev().name() });
    util.dumpf("{f}", .{tcpd.hdr});
    util.debugdump(data);

    const seg: SegInfo = .init(tcpd);
    pcb_table.segmentArrives(seg, tcpd.payload, tcpd.hdr.dst, tcpd.hdr.src) catch |err| {
        util.errorf(@src(), "pcb_table.segmentArrives() failure: {t}", .{err});
    };
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

fn replyRst(seg: SegInfo, local: udp.SocketAddr, remote: udp.SocketAddr) !void {
    if (!seg.flg.ack) {
        _ = try outputSegment(0, seg.seq +% seg.len, .{ .rst = true, .ack = true }, 0, &[_]u8{}, local, remote);
    } else {
        _ = try outputSegment(seg.ack, 0, .{ .rst = true }, 0, &[_]u8{}, local, remote);
    }
}

fn timerHandler() void {
    pcb_table.timer();
}

pub const cmd = struct {
    pub fn open(local: udp.SocketAddr, remote: udp.SocketAddr, mode: Mode) !usize {
        return pcb_table.open(local, remote, mode) catch |err| {
            util.errorf(@src(), "pcb_table.open() failure: {t}", .{err});
            return err;
        };
    }

    pub fn socket() !usize {
        return pcb_table.socket() catch |err| {
            util.errorf(@src(), "pcb_table.socket() failure: {t}", .{err});
            return err;
        };
    }

    pub fn close(desc: usize) !void {
        return pcb_table.close(desc) catch |err| {
            util.errorf(@src(), "pcb_table.close() failure: {t}", .{err});
            return err;
        };
    }

    pub fn connect(desc: usize, remote: udp.SocketAddr) !void {
        return pcb_table.connect(desc, remote) catch |err| {
            util.errorf(@src(), "pcb_table.connect() failure: {t}", .{err});
            return err;
        };
    }

    pub fn bind(desc: usize, local: udp.SocketAddr) !void {
        return pcb_table.bind(desc, local) catch |err| {
            util.errorf(@src(), "pcb_table.bind() failure: {t}", .{err});
            return err;
        };
    }

    pub fn listen(desc: usize, backlog: usize) !void {
        return pcb_table.listen(desc, backlog) catch |err| {
            util.errorf(@src(), "pcb_table.close() failure: {t}", .{err});
            return err;
        };
    }

    pub fn accept(desc: usize) !AcceptResult {
        return pcb_table.accept(desc) catch |err| {
            util.errorf(@src(), "pcb_table.accept() failure: {t}", .{err});
            return err;
        };
    }

    pub fn send(desc: usize, data: []const u8) !usize {
        return pcb_table.send(desc, data) catch |err| {
            util.errorf(@src(), "pcb_table.send() failure: {t}", .{err});
            return err;
        };
    }

    pub fn receive(desc: usize, buf: []u8) !usize {
        return pcb_table.receive(desc, buf) catch |err| {
            util.errorf(@src(), "pcb_table.receive() failure: {t}", .{err});
            return err;
        };
    }
};
