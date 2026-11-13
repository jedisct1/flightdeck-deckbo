//! FlightDeck, a deck cipher built on a duplex cipher.
//!
//! A deck cipher has a key, takes a sequence of strings of any length, and can return any number of bytes after each of them.
//! These bytes depend on the key and on all the strings so far.
//!
//! There are two layers:
//! - `OverwriteDuplex`: a duplex cipher, as secure as (Turbo)SHAKE.
//! - `FlightDeck`: a deck cipher on top of a duplex cipher.
//!
//! FlightDeck: https://eprint.iacr.org/2026/2801
//! Overwrite duplex: https://eprint.iacr.org/2024/1618

const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const math = std.math;
const mem = std.mem;

const native_endian = @import("builtin").cpu.arch.endian();

const KeccakF = crypto.core.keccak.KeccakF;

/// SHAKE128-FlightDeck, with 128 bits of security.
pub const Shake128FlightDeck = FlightDeck(Shake128Duplex, 5120, 32);
/// SHAKE256-FlightDeck, with 256 bits of security.
pub const Shake256FlightDeck = FlightDeck(Shake256Duplex, 8192, 64);
/// TurboSHAKE128-FlightDeck, with 128 bits of security.
/// About twice as fast as SHAKE128-FlightDeck.
pub const TurboShake128FlightDeck = FlightDeck(TurboShake128Duplex, 5120, 32);
/// TurboSHAKE256-FlightDeck, with 256 bits of security.
/// About twice as fast as SHAKE256-FlightDeck.
pub const TurboShake256FlightDeck = FlightDeck(TurboShake256Duplex, 8192, 64);

/// The overwrite duplex that is as secure as SHAKE128.
pub const Shake128Duplex = OverwriteDuplex(128, 24, 0x9f);
/// The overwrite duplex that is as secure as SHAKE256.
pub const Shake256Duplex = OverwriteDuplex(256, 24, 0x9f);
/// The overwrite duplex that is as secure as TurboSHAKE128.
pub const TurboShake128Duplex = OverwriteDuplex(128, 12, 0x80);
/// The overwrite duplex that is as secure as TurboSHAKE256.
pub const TurboShake256Duplex = OverwriteDuplex(256, 12, 0x80);

/// The overwrite duplex construction, on top of Keccak-p[1600].
///
/// A duplex cipher takes blocks of up to `block_length` bytes.
/// After each block, it can return up to `block_length` bytes that depend on the key and on all the blocks so far.
///
/// Each block comes with a trailer: a few bits to tell apart blocks that are used for different things.
/// It's written as an integer, with the bits first, lowest one first, then a 1 to mark the end.
/// So 1 is the empty trailer, and 0 isn't a trailer at all.
///
/// Copy an instance to clone it.
///
/// `security_level` is in bits, and the sponge function behind it has a capacity twice as large.
/// `padding` is the last byte of a block of that sponge function.
pub fn OverwriteDuplex(comptime security_level: u11, comptime rounds: u5, comptime padding: u8) type {
    comptime assert(security_level > 0 and security_level <= 256 and security_level % 32 == 0);
    comptime assert(rounds <= KeccakF(1600).max_rounds);
    comptime assert(padding & 0x80 != 0);

    return struct {
        const Self = @This();

        const Permutation = KeccakF(1600);

        /// How many bytes a call can absorb, and how many it can return.
        pub const block_length: comptime_int = Permutation.block_bytes - 8 - security_level / 4;
        /// Recommended key length, in bytes.
        pub const key_length = security_level / 8;
        /// Maximum key length, in bytes.
        pub const key_length_max = block_length;
        /// A trailer of up to 5 bits, from 1 to 63.
        pub const Trailer = u6;

        st: Permutation = .{},
        offset: usize = block_length,

        /// Set the key, of up to `key_length_max` bytes.
        /// Nothing can be squeezed before the first call to `duplex`.
        pub fn init(key: []const u8) Self {
            assert(key.len <= key_length_max);
            var self: Self = .{};
            self.duplex(&.{}, key, 1);
            self.offset = block_length;
            return self;
        }

        /// A clone that can only be used to call `duplex`.
        /// It can't squeeze what is left of the current output.
        pub fn cloneCompact(self: *const Self) Self {
            var clone = self.*;
            clone.st.clear(0, block_length);
            clone.offset = block_length;
            return clone;
        }

        /// Absorb a block and its trailer, then squeeze `out`.
        /// `in` and `out` can be up to `block_length` bytes long.
        pub fn duplex(self: *Self, out: []u8, in: []const u8, trailer: Trailer) void {
            assert(in.len <= block_length);
            assert(out.len <= block_length);

            if (in.len == block_length) {
                self.st.setBytes(in);
                self.st.addByte(appendBit(trailer, 1), block_length);
            } else {
                self.st.clear(0, block_length);
                self.st.setBytes(in);
                self.st.addByte(0x01, in.len);
                self.st.addByte(appendBit(trailer, 0), block_length);
            }
            self.st.addByte(padding, block_length + 7);
            self.st.permuteR(rounds);

            self.st.extractBytes(out);
            self.offset = out.len;
        }

        /// Squeeze more bytes after a call to `duplex`, up to `block_length` bytes in total.
        pub fn squeeze(self: *Self, out: []u8) void {
            assert(out.len <= block_length - self.offset);

            if (self.offset == 0) {
                self.st.extractBytes(out);
            } else {
                var block: [block_length]u8 = undefined;
                self.st.extractBytes(block[0 .. self.offset + out.len]);
                @memcpy(out, block[self.offset..][0..out.len]);
            }
            self.offset += out.len;
        }

        /// Like `squeeze`, but XOR the output with `in`.
        /// `out` and `in` have the same length, and can be the same buffer.
        pub fn xor(self: *Self, out: []u8, in: []const u8) void {
            assert(out.len == in.len);
            assert(in.len <= block_length - self.offset);

            if (self.offset == 0) {
                self.st.xorBytes(out, in);
            } else {
                var block: [block_length]u8 = undefined;
                self.st.extractBytes(block[0 .. self.offset + in.len]);
                for (out, in, block[self.offset..][0..in.len]) |*o, i, k| o.* = i ^ k;
            }
            self.offset += in.len;
        }
    };
}

/// The FlightDeck deck cipher.
///
/// You use it like a duplex cipher (see `OverwriteDuplex`), but inputs and outputs can be as long as you want.
///
/// Copy an instance to clone it.
///
/// `Duplex` is a duplex cipher that looks like `OverwriteDuplex`.
/// Long inputs are cut into chunks of `chunk_length` bytes, and each chunk is summed up in `chaining_value_length` bytes.
pub fn FlightDeck(comptime Duplex: type, comptime chunk_length: usize, comptime chaining_value_length: usize) type {
    const block_length = Duplex.block_length;

    comptime assert(chunk_length > 0);
    comptime assert(chaining_value_length > 0 and chaining_value_length <= block_length);
    // Output blocks are numbered with a 64-bit integer, and that has to fit in a block.
    comptime assert(block_length >= @sizeOf(u64));

    return struct {
        const Self = @This();

        const no_output = math.maxInt(u64);

        /// Recommended key length, in bytes.
        pub const key_length = Duplex.key_length;
        /// Maximum key length, in bytes.
        pub const key_length_max = Duplex.key_length_max;
        /// A trailer of up to 4 bits, from 1 to 31.
        pub const Trailer = @Int(.unsigned, @bitSizeOf(Duplex.Trailer) - 1);

        d: Duplex,
        /// The current output block, after the first one.
        block: [block_length]u8 = undefined,
        offset: u64 = no_output,

        /// Set the key, of up to `key_length_max` bytes.
        /// Nothing can be squeezed before the first call to `duplex`.
        pub fn init(key: []const u8) Self {
            return .{ .d = .init(key) };
        }

        /// A clone that can only be used to call `duplex`.
        /// It can't squeeze what is left of the current output.
        pub fn cloneCompact(self: *const Self) Self {
            return .{ .d = self.d.cloneCompact() };
        }

        /// Absorb a string and its trailer, then squeeze `out`.
        /// `in` and `out` can be of any length.
        pub fn duplex(self: *Self, out: []u8, in: []const u8, trailer: Trailer) void {
            const last_trailer = appendBit(trailer, 1);

            if (in.len <= chunk_length) {
                absorb(&self.d, in, last_trailer);
            } else {
                // Every chunk after the first one starts from this state.
                const d0 = self.d.cloneCompact();
                var root: Root = .{ .d = &self.d };
                root.update(in[0..chunk_length]);
                var chunks = in[chunk_length..];
                while (chunks.len > 0) {
                    const chunk = chunks[0..@min(chunk_length, chunks.len)];
                    chunks = chunks[chunk.len..];
                    var cv: [chaining_value_length]u8 = undefined;
                    var d = d0;
                    absorb(&d, chunk, 4);
                    d.squeeze(&cv);
                    root.update(&cv);
                }
                root.final(last_trailer);
            }

            self.offset = 0;
            self.squeeze(out);
        }

        /// Squeeze more bytes after a call to `duplex`.
        pub fn squeeze(self: *Self, out: []u8) void {
            @memset(out, 0);
            self.xor(out, out);
        }

        /// Like `squeeze`, but XOR the output with `in`.
        /// `out` and `in` have the same length, and can be the same buffer.
        pub fn xor(self: *Self, out: []u8, in: []const u8) void {
            assert(out.len == in.len);
            assert(self.offset != no_output);
            assert(in.len < no_output - self.offset);

            var i: usize = 0;
            if (self.offset < block_length) {
                i = @min(block_length - self.offset, in.len);
                self.d.xor(out[0..i], in[0..i]);
                self.offset += i;
            }
            const used: usize = @intCast(self.offset % block_length);
            if (used != 0 and i < in.len) {
                const n = @min(block_length - used, in.len - i);
                xorBytes(out[i..][0..n], in[i..][0..n], self.block[used..][0..n]);
                self.offset += n;
                i += n;
            }

            if (i == in.len) return;

            // After the first block, each block comes from a compact clone that absorbed its index.
            var counter: [block_length]u8 = @splat(0);
            while (i < in.len) {
                const left = in.len - i;
                mem.writeInt(u64, counter[0..8], self.offset / block_length, .little);
                var d = self.d.cloneCompact();
                d.duplex(&.{}, &counter, 2);
                const n = @min(block_length, left);
                if (n == block_length) {
                    d.xor(out[i..][0..n], in[i..][0..n]);
                } else {
                    d.squeeze(&self.block);
                    xorBytes(out[i..], in[i..], self.block[0..n]);
                }
                self.offset += n;
                i += n;
            }
        }

        /// Absorb a string block by block. The last block gets `last_trailer`.
        fn absorb(d: *Duplex, in: []const u8, last_trailer: Duplex.Trailer) void {
            var left = in;
            while (left.len > block_length) : (left = left[block_length..]) {
                d.duplex(&.{}, left[0..block_length], 1);
            }
            d.duplex(&.{}, left, last_trailer);
        }

        /// Like `absorb`, for a string that comes in pieces.
        const Root = struct {
            d: *Duplex,
            buf: [block_length]u8 = undefined,
            len: usize = 0,

            fn update(self: *Root, bytes: []const u8) void {
                var left = bytes;
                if (left.len == 0) return;

                // Hold on to a block until we know it isn't the last one.
                if (self.len > 0) {
                    const n = @min(block_length - self.len, left.len);
                    @memcpy(self.buf[self.len..][0..n], left[0..n]);
                    self.len += n;
                    left = left[n..];
                    if (left.len == 0) return;
                    self.d.duplex(&.{}, &self.buf, 1);
                }
                while (left.len > block_length) : (left = left[block_length..]) {
                    self.d.duplex(&.{}, left[0..block_length], 1);
                }
                @memcpy(self.buf[0..left.len], left);
                self.len = left.len;
            }

            fn final(self: *Root, last_trailer: Duplex.Trailer) void {
                self.d.duplex(&.{}, self.buf[0..self.len], last_trailer);
            }
        };
    };
}

/// Append a bit to a trailer.
fn appendBit(trailer: anytype, bit: u1) @Int(.unsigned, @bitSizeOf(@TypeOf(trailer)) + 1) {
    const Extended = @Int(.unsigned, @bitSizeOf(@TypeOf(trailer)) + 1);
    assert(trailer != 0);
    const end = @as(Extended, 1) << math.log2_int(@TypeOf(trailer), trailer);
    return trailer + (end << bit);
}

/// XOR `in` with `key` into `out`. `out` and `in` can be the same buffer.
fn xorBytes(out: []u8, in: []const u8, key: []const u8) void {
    assert(out.len == in.len and out.len == key.len);

    // A plain loop over the three slices stays slow when `out` is `in`.
    var i: usize = 0;
    while (i + 8 <= out.len) : (i += 8) {
        const x = mem.readInt(u64, in[i..][0..8], native_endian) ^ mem.readInt(u64, key[i..][0..8], native_endian);
        mem.writeInt(u64, out[i..][0..8], x, native_endian);
    }
    while (i < out.len) : (i += 1) out[i] = in[i] ^ key[i];
}

test {
    _ = @import("flightdeck_test.zig");
}

// FlightDeck as written in Algorithm 3 of the paper.
fn ReferenceFlightDeck(comptime Duplex: type, comptime alpha: usize, comptime c: usize) type {
    const rho = Duplex.block_length;

    return struct {
        const Self = @This();

        d: Duplex,
        d_squeeze: Duplex = undefined,
        o: usize = undefined,

        fn duplexing(self: *Self, allocator: mem.Allocator, z: []u8, x: []const u8, e: u5) !void {
            var r: std.ArrayList(u8) = .empty;
            defer r.deinit(allocator);

            try r.appendSlice(allocator, x[0..@min(alpha, x.len)]);
            var i: usize = alpha;
            while (i < x.len) : (i += alpha) {
                var y = x[i..@min(i + alpha, x.len)];
                var d_prime = self.d.cloneCompact();
                while (y.len > rho) : (y = y[rho..]) d_prime.duplex(&.{}, y[0..rho], 1);
                var cv: [c]u8 = undefined;
                d_prime.duplex(&cv, y, 4);
                try r.appendSlice(allocator, &cv);
            }
            var left = r.items;
            while (left.len > rho) : (left = left[rho..]) self.d.duplex(&.{}, left[0..rho], 1);
            // E||1
            self.d.duplex(&.{}, left, @as(u6, e) + (@as(u6, 2) << math.log2_int(u5, e)));
            self.o = 0;
            self.squeezing(z);
        }

        fn squeezing(self: *Self, z: []u8) void {
            var done: usize = 0;
            if (self.o <= rho) {
                done = @min(rho - self.o, z.len);
                self.d.squeeze(z[0..done]);
                self.o += done;
            }
            while (done < z.len) {
                if (self.o % rho == 0) {
                    var counter: [rho]u8 = @splat(0);
                    mem.writeInt(u64, counter[0..8], self.o / rho, .little);
                    self.d_squeeze = self.d.cloneCompact();
                    self.d_squeeze.duplex(&.{}, &counter, 2);
                }
                const n = @min(rho - self.o % rho, z.len - done);
                self.d_squeeze.squeeze(z[done..][0..n]);
                self.o += n;
                done += n;
            }
        }
    };
}

test "FlightDeck against the reference algorithm" {
    const allocator = std.testing.allocator;

    inline for (.{
        .{ TurboShake128Duplex, 5120, 32 },
        // Chunks that don't end on a block boundary, chaining values that don't end on a lane boundary.
        .{ TurboShake128Duplex, 327, 13 },
        // One block per chunk, chaining values as long as a block.
        .{ TurboShake256Duplex, 128, 128 },
    }) |parameters| {
        const Duplex, const alpha, const c = parameters;
        const rho = Duplex.block_length;

        var reference: ReferenceFlightDeck(Duplex, alpha, c) = .{ .d = .init("key") };
        var deck: FlightDeck(Duplex, alpha, c) = .init("key");

        const in = try allocator.alloc(u8, 18 * alpha + rho + 1);
        defer allocator.free(in);
        for (in, 0..) |*b, i| b.* = @truncate(5 * i + 1);
        var expected: [20 * rho]u8 = undefined;
        var out: [expected.len]u8 = undefined;

        var prng: std.Random.DefaultPrng = .init(alpha);
        const random = prng.random();

        // Lengths around every multiple of half a chunk.
        for (0..37) |half_chunks| {
            for ([_]usize{ 0, 1, 2, rho + 1, rho + 2 }) |extra| {
                const x = in[0..half_chunks * alpha / 2 + extra -| 1];
                const trailer = random.intRangeAtMost(u5, 1, 31);
                const z = out[0..random.uintAtMost(usize, out.len)];
                const second = random.uintAtMost(usize, z.len);
                const first = random.uintAtMost(usize, second);

                try reference.duplexing(allocator, expected[0..z.len], x, trailer);
                // The same output, in three pieces.
                deck.duplex(z[0..first], x, trailer);
                deck.squeeze(z[first..second]);
                deck.squeeze(z[second..]);
                try std.testing.expectEqualSlices(u8, expected[0..z.len], z);
            }
        }
    }
}
