//! Throughput of the FlightDeck instances and of the authenticated encryption schemes built on them.
//!
//! zig build bench

const std = @import("std");
const Io = std.Io;
const mem = std.mem;

const flightdeck = @import("flightdeck");

const key: [32]u8 = @splat(0x42);
const sizes = [_]usize{ 64, 1024, 8192, 65536, 1 << 20 };
const min_duration_ns = 100 * std.time.ns_per_ms;

fn now(io: Io) i96 {
    return Io.Clock.awake.now(io).nanoseconds;
}

/// Run `op` repeatedly on `size` bytes and return the best throughput seen, in MiB/s.
fn measure(io: Io, size: usize, context: anytype, comptime op: fn (@TypeOf(context)) void) f64 {
    var best: f64 = 0;
    for (0..5) |_| {
        var iterations: usize = 0;
        const start = now(io);
        var elapsed: i96 = 0;
        while (elapsed < min_duration_ns / 5) : (elapsed = now(io) - start) {
            for (0..16) |_| op(context);
            iterations += 16;
        }
        const bytes: f64 = @floatFromInt(iterations * size);
        const nanoseconds: f64 = @floatFromInt(elapsed);
        best = @max(best, bytes / (nanoseconds / std.time.ns_per_s) / (1 << 20));
    }
    return best;
}

fn Buffers(comptime T: type) type {
    return struct {
        state: T,
        in: []u8,
        out: []u8,
    };
}

fn absorb(comptime Deck: type) fn (*Buffers(Deck)) void {
    return struct {
        fn op(b: *Buffers(Deck)) void {
            var deck = b.state;
            var out: [32]u8 = undefined;
            deck.duplex(&out, b.in, 1);
            mem.doNotOptimizeAway(&out);
        }
    }.op;
}

fn squeeze(comptime Deck: type) fn (*Buffers(Deck)) void {
    return struct {
        fn op(b: *Buffers(Deck)) void {
            var deck = b.state;
            deck.duplex(&.{}, "", 1);
            deck.xor(b.out, b.in);
            mem.doNotOptimizeAway(b.out.ptr);
        }
    }.op;
}

fn encrypt(comptime Aead: type) fn (*Buffers(Aead)) void {
    return struct {
        fn op(b: *Buffers(Aead)) void {
            var aead = b.state;
            var tag: [Aead.tag_length]u8 = undefined;
            aead.encrypt(b.out, &tag, b.in, "");
            mem.doNotOptimizeAway(&tag);
            mem.doNotOptimizeAway(b.out.ptr);
        }
    }.op;
}

fn kangarooTwelve(b: *Buffers(void)) void {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha3.KT128.hash(b.in, &out, .{}) catch unreachable;
    mem.doNotOptimizeAway(&out);
}

/// Print the throughput of every instance, for a few message lengths.
pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();

    var stdout_buffer: [256]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(io, &stdout_buffer);
    const stdout = &stdout_writer.interface;

    const in = try arena.alloc(u8, sizes[sizes.len - 1]);
    const out = try arena.alloc(u8, in.len);
    for (in, 0..) |*b, i| b.* = @truncate(i *% 31);

    try stdout.print("{s:<34}", .{"MiB/s"});
    for (sizes) |size| try stdout.print("{d:>10}", .{size});
    try stdout.print("\n", .{});

    const decks = .{
        .{ "TurboSHAKE128-FlightDeck", flightdeck.TurboShake128FlightDeck },
        .{ "TurboSHAKE256-FlightDeck", flightdeck.TurboShake256FlightDeck },
        .{ "SHAKE128-FlightDeck", flightdeck.Shake128FlightDeck },
        .{ "SHAKE256-FlightDeck", flightdeck.Shake256FlightDeck },
    };
    inline for (.{ "input", "output" }, .{ absorb, squeeze }) |direction, op| {
        inline for (decks) |deck| {
            const name, const Deck = deck;
            try stdout.print("{s:<34}", .{name ++ " " ++ direction});
            for (sizes) |size| {
                var buffers: Buffers(Deck) = .{ .state = .init(&key), .in = in[0..size], .out = out[0..size] };
                try stdout.print("{d:>10.0}", .{measure(io, size, &buffers, op(Deck))});
                try stdout.flush();
            }
            try stdout.print("\n", .{});
        }
    }

    const aeads = .{
        .{ "TurboSHAKE128-BO", flightdeck.TurboShake128Bo(16) },
        .{ "TurboSHAKE256-BO", flightdeck.TurboShake256Bo(32) },
        .{ "SHAKE128-BO", flightdeck.Shake128Bo(16) },
        .{ "SHAKE256-BO", flightdeck.Shake256Bo(32) },
    };
    inline for (aeads) |aead| {
        const name, const Aead = aead;
        try stdout.print("{s:<34}", .{name ++ " encrypt"});
        for (sizes) |size| {
            var buffers: Buffers(Aead) = .{ .state = .init(&key), .in = in[0..size], .out = out[0..size] };
            try stdout.print("{d:>10.0}", .{measure(io, size, &buffers, encrypt(Aead))});
            try stdout.flush();
        }
        try stdout.print("\n", .{});
    }

    try stdout.print("{s:<34}", .{"KT128 (std, for reference)"});
    for (sizes) |size| {
        var buffers: Buffers(void) = .{ .state = {}, .in = in[0..size], .out = out[0..size] };
        try stdout.print("{d:>10.0}", .{measure(io, size, &buffers, kangarooTwelve)});
        try stdout.flush();
    }
    try stdout.print("\n", .{});
    try stdout.flush();
}
