//! FlightDeck, a deck cipher that processes long inputs and long outputs in parallel.
//!
//! A deck cipher has a key, takes slices of bytes of any length, and can return any number of bytes after each of them.
//! These bytes depend on the key and on all the inputs so far.
//!
//! - `OverwriteDuplex`: a duplex cipher, as secure as (Turbo)SHAKE. `FlightDeck` is built on it.
//! - `FlightDeck`: a deck cipher on top of a duplex cipher. Use `TurboShake128FlightDeck` and its siblings.
//! - `DeckBo`: authenticated encryption on top of a deck cipher. Use `TurboShake128Bo()` and its siblings.
//!
//! Keys are normally `key_length` random bytes, and can be anything up to `key_length_max` bytes.
//! `DeckBo` works on sessions and has no nonce: the same message at the same point of a session gets the same ciphertext.
//!
//! FlightDeck: https://eprint.iacr.org/2026/2801
//! Overwrite duplex and Deck-BO: https://eprint.iacr.org/2024/1618

const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const math = std.math;
const mem = std.mem;
const simd = std.simd;

const AuthenticationError = crypto.errors.AuthenticationError;
const KeccakF = crypto.core.keccak.KeccakF;

/// SHAKE128-FlightDeck, a deck cipher with 128 bits of security.
pub const Shake128FlightDeck = FlightDeck(Shake128Duplex, 5120, 32);
/// SHAKE256-FlightDeck, a deck cipher with 256 bits of security.
pub const Shake256FlightDeck = FlightDeck(Shake256Duplex, 8192, 64);
/// TurboSHAKE128-FlightDeck, about twice as fast as `Shake128FlightDeck`.
pub const TurboShake128FlightDeck = FlightDeck(TurboShake128Duplex, 5120, 32);
/// TurboSHAKE256-FlightDeck, about twice as fast as `Shake256FlightDeck`.
pub const TurboShake256FlightDeck = FlightDeck(TurboShake256Duplex, 8192, 64);

/// The overwrite duplex that is as secure as SHAKE128.
pub const Shake128Duplex = OverwriteDuplex(128, 24, 0x9f);
/// The overwrite duplex that is as secure as SHAKE256.
pub const Shake256Duplex = OverwriteDuplex(256, 24, 0x9f);
/// The overwrite duplex that is as secure as TurboSHAKE128.
pub const TurboShake128Duplex = OverwriteDuplex(128, 12, 0x80);
/// The overwrite duplex that is as secure as TurboSHAKE256.
pub const TurboShake256Duplex = OverwriteDuplex(256, 12, 0x80);

/// SHAKE128-BO, authenticated encryption with 128 bits of security.
/// `tag_len` is in bytes, see `DeckBo`.
pub fn Shake128Bo(comptime tag_len: usize) type {
    return DeckBo(Shake128FlightDeck, tag_len);
}

/// SHAKE256-BO, authenticated encryption with 256 bits of security.
/// `tag_len` is in bytes, see `DeckBo`.
pub fn Shake256Bo(comptime tag_len: usize) type {
    return DeckBo(Shake256FlightDeck, tag_len);
}

/// TurboSHAKE128-BO, authenticated encryption with 128 bits of security.
/// `tag_len` is in bytes, see `DeckBo`.
pub fn TurboShake128Bo(comptime tag_len: usize) type {
    return DeckBo(TurboShake128FlightDeck, tag_len);
}

/// TurboSHAKE256-BO, authenticated encryption with 256 bits of security.
/// `tag_len` is in bytes, see `DeckBo`.
pub fn TurboShake256Bo(comptime tag_len: usize) type {
    return DeckBo(TurboShake256FlightDeck, tag_len);
}

/// The overwrite duplex construction, on top of Keccak-p[1600].
///
/// It takes blocks of up to `block_length` bytes, and can return up to `block_length` bytes after each of them.
/// These bytes depend on the key and on all the blocks so far.
///
/// A trailer is a few domain separation bits, least significant bit first, followed by a 1 bit.
/// So 1 is the empty trailer, and 0 isn't a trailer.
///
/// `padding` is the last byte of a block of the sponge function it is as secure as.
pub fn OverwriteDuplex(comptime security_level: u11, comptime rounds: u5, comptime padding: u8) type {
    comptime assert(security_level > 0 and security_level <= 256 and security_level % 32 == 0);
    comptime assert(rounds <= KeccakF(1600).max_rounds);
    comptime assert(padding & 0x80 != 0);

    return struct {
        const Self = @This();

        const Permutation = KeccakF(1600);
        const block_lanes = block_length / 8;

        /// Maximum length of a block, and of the output of a call, in bytes.
        pub const block_length: comptime_int = Permutation.block_bytes - 8 - security_level / 4;
        /// Recommended key length, in bytes.
        pub const key_length = security_level / 8;
        /// Minimum key length, in bytes.
        pub const key_length_min = 0;
        /// Maximum key length, in bytes.
        pub const key_length_max = block_length;
        /// A trailer of up to 5 bits, from 1 to 63.
        pub const Trailer = u6;
        /// How many clones `Parallel()` should process at once on this target.
        pub const optimal_parallel_blocks = simd.suggestVectorLength(u64) orelse 1;

        st: Permutation = .{},
        offset: usize = block_length,

        /// Set the key. Nothing can be squeezed before the first call to `duplex()`.
        pub fn init(key: []const u8) Self {
            assert(key.len <= key_length_max);
            var self: Self = .{};
            self.duplex(&.{}, key, 0b1);
            self.offset = block_length;
            return self;
        }

        /// A clone that can only call `duplex()`: it can't squeeze what's left of the current output.
        pub fn cloneCompact(self: *const Self) Self {
            var clone = self.*;
            clone.st.clear(0, block_length);
            clone.offset = block_length;
            return clone;
        }

        /// Absorb a block and its trailer, then squeeze `out`.
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

        /// Squeeze more bytes after a call to `duplex()`, up to `block_length` bytes in total.
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

        /// Like `squeeze()`, but XOR the output with `in`. They can be the same buffer.
        pub fn xor(self: *Self, out: []u8, in: []const u8) void {
            assert(out.len == in.len);
            assert(in.len <= block_length - self.offset);

            if (self.offset == 0) {
                self.st.xorBytes(out, in);
            } else {
                // xorBytes() starts at the first byte of the state, so line the input up with the output.
                const end = self.offset + in.len;
                var block: [block_length]u8 = @splat(0);
                @memcpy(block[self.offset..end], in);
                self.st.xorBytes(block[0..end], block[0..end]);
                @memcpy(out, block[self.offset..end]);
            }
            self.offset += in.len;
        }

        /// `n` compact clones of a duplex cipher, processed together using vectors. `n` is a power of two.
        pub fn Parallel(comptime n: comptime_int) type {
            comptime assert(n >= 2 and math.isPowerOfTwo(n));

            return struct {
                const Clones = @This();

                st: [25]@Vector(n, u64),

                /// Make `n` compact clones of `d`.
                pub fn init(d: *const Self) Clones {
                    var self: Clones = undefined;
                    inline for (&self.st, d.st.st, 0..) |*lanes, lane, i| {
                        lanes.* = @splat(if (i < block_lanes) 0 else lane);
                    }
                    return self;
                }

                /// The clone `i`, as a duplex cipher of its own.
                pub fn get(self: *const Clones, i: usize) Self {
                    var d: Self = .{ .offset = 0 };
                    inline for (&d.st.st, self.st) |*lane, lanes| {
                        const clones: [n]u64 = lanes;
                        lane.* = clones[i];
                    }
                    return d;
                }

                /// Make each clone absorb its own block.
                /// Inlined so that the states stay in registers from one block to the next.
                pub inline fn duplex(self: *Clones, comptime len: usize, blocks: [n]*const [len]u8, trailer: Trailer) void {
                    comptime assert(len <= block_length);

                    if (len == block_length) {
                        self.overwrite(blocks);
                    } else {
                        var padded: [n][block_length]u8 = @splat(@splat(0));
                        var padded_blocks: [n]*const [block_length]u8 = undefined;
                        inline for (&padded, &padded_blocks, blocks) |*buf, *padded_block, block| {
                            buf[0..len].* = block.*;
                            buf[len] = 0x01;
                            padded_block.* = buf;
                        }
                        self.overwrite(padded_blocks);
                    }
                    const first: u64 = appendBit(trailer, @intFromBool(len == block_length));
                    const last: u64 = padding;
                    self.st[block_lanes] ^= @splat(first | (last << 56));
                    permute(n, rounds, &self.st);
                }

                /// Squeeze `len` bytes from each clone, one clone after the other.
                pub fn squeeze(self: *const Clones, comptime len: usize, out: *[n * len]u8) void {
                    self.output(len, out, null);
                }

                /// Like `squeeze()`, but XOR the output with `in`. They can be the same buffer.
                pub fn xor(self: *const Clones, comptime len: usize, out: *[n * len]u8, in: *const [n * len]u8) void {
                    self.output(len, out, in);
                }

                /// A vector of the state holds the same lane of every clone, but a block holds consecutive lanes of one clone.
                /// So load the blocks as rows, and transpose them.
                inline fn overwrite(self: *Clones, blocks: [n]*const [block_length]u8) void {
                    @setEvalBranchQuota(100_000);
                    comptime var from = 0;
                    inline while (from < block_lanes) : (from += n) {
                        const count: comptime_int = @min(n, block_lanes - from);
                        var rows: [n]@Vector(n, u64) = undefined;
                        inline for (&rows, blocks) |*row, block| {
                            var lanes: [n]u64 = @splat(0);
                            lanes[0..count].* = mem.littleToNative(@Vector(count, u64), mem.bytesToValue([count]u64, block[8 * from ..][0 .. 8 * count]));
                            row.* = lanes;
                        }
                        transpose(n, &rows);
                        self.st[from..][0..count].* = rows[0..count].*;
                    }
                }

                /// The reverse of `overwrite()`.
                inline fn output(self: *const Clones, comptime len: usize, out: *[n * len]u8, in: ?*const [n * len]u8) void {
                    comptime assert(len <= block_length);
                    @setEvalBranchQuota(100_000);

                    comptime var from = 0;
                    inline while (8 * from < len) : (from += n) {
                        const count: comptime_int = @min(n, block_lanes - from);
                        const size: comptime_int = @min(8 * count, len - 8 * from);
                        var rows: [n]@Vector(n, u64) = @splat(@splat(0));
                        rows[0..count].* = self.st[from..][0..count].*;
                        transpose(n, &rows);
                        inline for (rows, 0..) |row, i| {
                            const at = i * len + 8 * from;
                            const whole = size / 8;
                            const lanes: [n]u64 = row;
                            if (whole > 0) {
                                const bytes = out[at..][0 .. 8 * whole];
                                const Part = @Vector(whole, u64);
                                var part: Part = lanes[0..whole].*;
                                if (in) |src| part ^= mem.littleToNative(Part, mem.bytesToValue([whole]u64, src[at..][0 .. 8 * whole]));
                                mem.bytesAsValue([whole]u64, bytes).* = mem.nativeToLittle(Part, part);
                            }
                            if (size % 8 != 0) {
                                var last: [8]u8 = undefined;
                                mem.writeInt(u64, &last, lanes[whole], .little);
                                inline for (at + 8 * whole..at + size, 0..) |k, j| {
                                    out[k] = last[j] ^ if (in) |src| src[k] else 0;
                                }
                            }
                        }
                    }
                }
            };
        }
    };
}

/// The FlightDeck deck cipher: like a duplex cipher (see `OverwriteDuplex`), with inputs and outputs of any length.
///
/// `Duplex` is a duplex cipher that looks like `OverwriteDuplex`. `Parallel()` and `optimal_parallel_blocks` are optional.
/// Long inputs are cut into chunks of `chunk_length` bytes, each summed up in `chaining_value_length` bytes.
pub fn FlightDeck(comptime Duplex: type, comptime chunk_length: usize, comptime chaining_value_length: usize) type {
    const block_length = Duplex.block_length;

    comptime assert(chunk_length > 0);
    comptime assert(chaining_value_length > 0 and chaining_value_length <= block_length);
    // The 64-bit counter of output blocks has to fit in a block.
    comptime assert(block_length >= @sizeOf(u64));

    return struct {
        const Self = @This();

        const batch_sizes: []const comptime_int = if (@hasDecl(Duplex, "Parallel")) switch (Duplex.optimal_parallel_blocks) {
            1 => &.{},
            2, 3 => &.{2},
            4...7 => &.{ 2, 4 },
            else => &.{ 2, 4, 8 },
        } else &.{};
        const max_batch_size = if (batch_sizes.len == 0) 1 else batch_sizes[batch_sizes.len - 1];
        const blocks_per_chunk = @divCeil(chunk_length, block_length);
        const last_block_length = (chunk_length - 1) % block_length + 1;

        const no_trailer = 0b1;
        const counter_trailer = 0b10;
        const chaining_value_trailer = 0b100;

        /// Recommended key length, in bytes.
        pub const key_length = Duplex.key_length;
        /// Minimum key length, in bytes.
        pub const key_length_min = Duplex.key_length_min;
        /// Maximum key length, in bytes.
        pub const key_length_max = Duplex.key_length_max;
        /// A trailer of up to 4 bits, from 1 to 31.
        pub const Trailer = @Int(.unsigned, @bitSizeOf(Duplex.Trailer) - 1);

        d: Duplex,
        /// A clone of `d` that gives the current output block, after the first one.
        d_squeeze: Duplex = undefined,
        /// How many bytes of output were squeezed, or null before the first call to `duplex()`.
        offset: ?u64 = null,

        /// Set the key. Nothing can be squeezed before the first call to `duplex()`.
        pub fn init(key: []const u8) Self {
            return .{ .d = .init(key) };
        }

        /// A clone that can only call `duplex()`: it can't squeeze what's left of the current output.
        pub fn cloneCompact(self: *const Self) Self {
            return .{ .d = self.d.cloneCompact() };
        }

        /// Absorb a slice of bytes of any length and its trailer, then squeeze `out`.
        pub fn duplex(self: *Self, out: []u8, in: []const u8, trailer: Trailer) void {
            const last_trailer = appendBit(trailer, 1);

            if (in.len <= chunk_length) {
                absorb(&self.d, in, last_trailer);
            } else {
                // Every chunk after the first one starts from this state.
                const d0 = self.d.cloneCompact();
                var root: Root = .{ .d = &self.d };
                var chunks = in;
                var first = true;

                batches: while (true) {
                    const full = chunks.len / chunk_length;
                    // A shorter last chunk can join a batch, except for its last block.
                    const tail_blocks = (chunks.len % chunk_length -| 1) / block_length;
                    // A batch doesn't have to be full to be worth it.
                    // A shorter last chunk only calls for a bigger batch if it's at least half a chunk.
                    const wanted = full + @intFromBool(2 * tail_blocks >= blocks_per_chunk);
                    if (wanted < 2) break;

                    inline for (batch_sizes) |n| {
                        if (wanted <= n or n == max_batch_size) {
                            const count = @min(full, n);
                            const tail_length = if (count == full and count < n) tail_blocks * block_length else 0;
                            var tail: Duplex = undefined;

                            var clones: Duplex.Parallel(n) = .init(&d0);
                            var done: usize = 0;
                            while (true) : (done += block_length) {
                                if (tail_length != 0 and done == tail_length) tail = clones.get(count);
                                if (done == chunk_length - last_block_length) break;
                                clones.duplex(block_length, blocksOf(n, block_length, chunks, count, tail_length, done), no_trailer);
                            }
                            if (first) {
                                // The first clone played the main duplex. The end of its chunk may share a block with chaining values.
                                self.d = clones.get(0);
                                root.update(chunks[done..chunk_length]);
                            }
                            clones.duplex(last_block_length, blocksOf(n, last_block_length, chunks, count, tail_length, done), chaining_value_trailer);

                            var cvs: [n][chaining_value_length]u8 = undefined;
                            clones.squeeze(chaining_value_length, mem.asBytes(&cvs));
                            root.update(mem.sliceAsBytes(cvs[@intFromBool(first)..count]));
                            chunks = chunks[count * chunk_length ..];
                            if (tail_length != 0) {
                                tail.duplex(&cvs[0], chunks[tail_length..], chaining_value_trailer);
                                root.update(&cvs[0]);
                                chunks = chunks[chunks.len..];
                            }
                            first = false;
                            continue :batches;
                        }
                    }
                    break;
                }
                if (first) {
                    root.update(chunks[0..chunk_length]);
                    chunks = chunks[chunk_length..];
                }
                while (chunks.len > 0) {
                    const chunk = chunks[0..@min(chunk_length, chunks.len)];
                    chunks = chunks[chunk.len..];
                    var cv: [chaining_value_length]u8 = undefined;
                    var d = d0;
                    absorb(&d, chunk, chaining_value_trailer);
                    d.squeeze(&cv);
                    root.update(&cv);
                }
                root.final(last_trailer);
            }

            self.offset = 0;
            self.squeeze(out);
        }

        /// Squeeze more bytes after a call to `duplex()`.
        pub fn squeeze(self: *Self, out: []u8) void {
            @memset(out, 0);
            self.xor(out, out);
        }

        /// Like `squeeze()`, but XOR the output with `in`. They can be the same buffer.
        pub fn xor(self: *Self, out: []u8, in: []const u8) void {
            assert(out.len == in.len);
            var offset = self.offset.?;
            defer self.offset = offset;
            assert(in.len <= math.maxInt(u64) - offset);

            var i: usize = 0;
            if (offset < block_length) {
                i = @min(block_length - offset, in.len);
                self.d.xor(out[0..i], in[0..i]);
                offset += i;
            }
            const used: usize = @intCast(offset % block_length);
            if (used != 0 and i < in.len) {
                const n = @min(block_length - used, in.len - i);
                self.d_squeeze.xor(out[i..][0..n], in[i..][0..n]);
                offset += n;
                i += n;
            }

            if (i == in.len) return;

            // After the first block, each block comes from a compact clone that absorbed its index.
            var counters: [max_batch_size][block_length]u8 = @splat(@splat(0));
            batches: while (i < in.len) {
                const left = in.len - i;
                const index = offset / block_length;
                const needed = @divCeil(left, block_length);

                if (needed >= 2) inline for (batch_sizes) |n| {
                    if (needed <= n or n == max_batch_size) {
                        var blocks: [n]*const [block_length]u8 = undefined;
                        inline for (&blocks, counters[0..n], 0..) |*block, *counter, j| {
                            mem.writeInt(u64, counter[0..8], index + j, .little);
                            block.* = counter;
                        }
                        var clones: Duplex.Parallel(n) = .init(&self.d);
                        clones.duplex(block_length, blocks, counter_trailer);

                        const batch_length = n * block_length;
                        if (left >= batch_length) {
                            clones.xor(block_length, out[i..][0..batch_length], in[i..][0..batch_length]);
                            offset += batch_length;
                            i += batch_length;
                        } else {
                            var batch: [batch_length]u8 = undefined;
                            clones.squeeze(block_length, &batch);
                            // Whole vectors, since a loop over the slices is slow when `out` is `in`.
                            const Block = @Vector(block_length, u8);
                            for (0..left / block_length) |j| {
                                const x: Block = in[i..][0..block_length].*;
                                const k: Block = batch[j * block_length ..][0..block_length].*;
                                out[i..][0..block_length].* = x ^ k;
                                offset += block_length;
                                i += block_length;
                            }
                            // The clone of a last, shorter block is kept for the next call.
                            if (i < in.len) {
                                self.d_squeeze = clones.get(needed - 1);
                                self.d_squeeze.xor(out[i..], in[i..]);
                                offset += in.len - i;
                                i = in.len;
                            }
                        }
                        continue :batches;
                    }
                };

                mem.writeInt(u64, counters[0][0..8], index, .little);
                self.d_squeeze = self.d.cloneCompact();
                self.d_squeeze.duplex(&.{}, &counters[0], counter_trailer);
                const n = @min(block_length, left);
                self.d_squeeze.xor(out[i..][0..n], in[i..][0..n]);
                offset += n;
                i += n;
            }
        }

        /// The block of each clone, at `offset` in its chunk.
        /// The first `count` chunks are full, and the next one is in for `tail_length` bytes.
        /// A clone with nothing to do gets the block of the first clone again.
        inline fn blocksOf(
            comptime n: comptime_int,
            comptime len: usize,
            chunks: []const u8,
            count: usize,
            tail_length: usize,
            offset: usize,
        ) [n]*const [len]u8 {
            var blocks: [n]*const [len]u8 = undefined;
            inline for (&blocks, 0..) |*block, i| {
                const chunk = if (i < count or (i == count and offset < tail_length)) i else 0;
                block.* = chunks[chunk * chunk_length + offset ..][0..len];
            }
            return blocks;
        }

        /// Absorb a slice of bytes block by block. The last block gets `last_trailer`.
        fn absorb(d: *Duplex, in: []const u8, last_trailer: Duplex.Trailer) void {
            var left = in;
            while (left.len > block_length) : (left = left[block_length..]) {
                d.duplex(&.{}, left[0..block_length], no_trailer);
            }
            d.duplex(&.{}, left, last_trailer);
        }

        /// Like `absorb()`, for an input that comes in pieces.
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
                    self.d.duplex(&.{}, &self.buf, no_trailer);
                }
                while (left.len > block_length) : (left = left[block_length..]) {
                    self.d.duplex(&.{}, left[0..block_length], no_trailer);
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

/// The Deck-BO authenticated encryption mode, on top of a deck cipher such as `FlightDeck`.
///
/// An instance is a session: each message is authenticated along with all the ones before it.
/// There is no nonce, so the same message at the same point of a session gets the same ciphertext.
/// If that's a problem, put a nonce or a counter in the associated data.
///
/// `tag_len` is in bytes. A forgery succeeds with probability 2^-(8 * tag_len).
/// A tag twice as long as the security level, 32 bytes for 128 bits, also commits to the key, the associated data and the message.
pub fn DeckBo(comptime Deck: type, comptime tag_len: usize) type {
    comptime assert(tag_len > 0);

    return struct {
        const Self = @This();

        /// Length of the authentication tag, in bytes.
        pub const tag_length = tag_len;
        /// Recommended key length, in bytes.
        pub const key_length = Deck.key_length;
        /// Minimum key length, in bytes.
        pub const key_length_min = Deck.key_length_min;
        /// Maximum key length, in bytes.
        pub const key_length_max = Deck.key_length_max;

        const ad_only_trailer = 0b100;
        const ad_trailer = 0b101;
        const tag_trailer = 0b1101;
        const message_trailer = 0b1110;

        deck: Deck,

        /// Start a session.
        pub fn init(key: []const u8) Self {
            return .{ .deck = .init(key) };
        }

        /// Encrypt the next message of the session.
        /// `c`: ciphertext, same length as `m`. They can be the same buffer.
        /// `tag`: authentication tag
        /// `m`: message
        /// `ad`: associated data
        pub fn encrypt(self: *Self, c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8) void {
            assert(c.len == m.len);

            if (m.len == 0) {
                self.deck.duplex(tag, ad, ad_only_trailer);
                return;
            }
            if (ad.len != 0) self.deck.duplex(&.{}, ad, ad_trailer);
            var keystream = self.deck.cloneCompact();
            self.deck.duplex(tag, m, message_trailer);
            keystream.duplex(&.{}, tag, tag_trailer);
            keystream.xor(c, m);
        }

        /// Decrypt the next message of the session.
        /// `m`: message, same length as `c`. They can be the same buffer.
        /// `c`: ciphertext
        /// `tag`: authentication tag
        /// `ad`: associated data
        ///
        /// If the tag doesn't match, `m` is zeroed and the session stays as it was.
        pub fn decrypt(self: *Self, m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8) AuthenticationError!void {
            assert(c.len == m.len);

            var deck = self.deck.cloneCompact();
            var computed_tag: [tag_length]u8 = undefined;
            if (c.len == 0) {
                deck.duplex(&computed_tag, ad, ad_only_trailer);
            } else {
                if (ad.len != 0) deck.duplex(&.{}, ad, ad_trailer);
                var keystream = deck.cloneCompact();
                keystream.duplex(&.{}, &tag, tag_trailer);
                keystream.xor(m, c);
                deck.duplex(&computed_tag, m, message_trailer);
            }
            if (!crypto.timing_safe.eql([tag_length]u8, computed_tag, tag)) {
                crypto.secureZero(u8, m);
                return error.AuthenticationFailed;
            }
            self.deck = deck;
        }
    };
}

fn appendBit(trailer: anytype, bit: u1) @Int(.unsigned, @bitSizeOf(@TypeOf(trailer)) + 1) {
    const Extended = @Int(.unsigned, @bitSizeOf(@TypeOf(trailer)) + 1);
    assert(trailer != 0);
    const one: Extended = 1;
    const end = one << math.log2_int(@TypeOf(trailer), trailer);
    return trailer + (end << bit);
}

fn transpose(comptime n: comptime_int, rows: *[n]@Vector(n, u64)) void {
    comptime assert(n >= 2 and math.isPowerOfTwo(n));
    const half = n / 2;
    const quarter = n / 4;

    // Transpose every 2x2 block first.
    // After that, elements only move in pairs, which is cheap with 128-bit registers.
    var pairs: [2][half]@Vector(n, u64) = undefined;
    inline for (0..half) |i| {
        const a = simd.deinterlace(2, rows[2 * i]);
        const b = simd.deinterlace(2, rows[2 * i + 1]);
        pairs[0][i] = simd.interlace(.{ a[0], b[0] });
        pairs[1][i] = simd.interlace(.{ a[1], b[1] });
    }
    // Then split the pairs at even and at odd positions until they're all in place.
    inline for (&pairs) |*matrix| {
        inline for (0..math.log2(half)) |_| {
            const previous = matrix.*;
            inline for (0..quarter) |i| {
                const a = simd.deinterlace(4, previous[2 * i]);
                const b = simd.deinterlace(4, previous[2 * i + 1]);
                matrix[i] = simd.join(simd.interlace(.{ a[0], a[1] }), simd.interlace(.{ b[0], b[1] }));
                matrix[i + quarter] = simd.join(simd.interlace(.{ a[2], a[3] }), simd.interlace(.{ b[2], b[3] }));
            }
        }
    }
    inline for (0..half) |i| {
        rows[2 * i] = pairs[0][i];
        rows[2 * i + 1] = pairs[1][i];
    }
}

/// Keccak-p[1600] on `n` states at once. `st[i]` is the lane `i` of every state.
inline fn permute(comptime n: comptime_int, comptime rounds: u5, st: *[25]@Vector(n, u64)) void {
    @setEvalBranchQuota(100_000);
    const Lanes = @Vector(n, u64);
    const round_constants = [24]u64{
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    };
    const pi = [24]u5{
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    };

    for (round_constants[round_constants.len - rounds ..]) |round_constant| {
        var t: [5]Lanes = undefined;
        inline for (&t, 0..) |*parity, x| {
            parity.* = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
        }
        inline for (0..5) |x| {
            const d = t[(x + 4) % 5] ^ math.rotl(Lanes, t[(x + 1) % 5], 1);
            inline for (0..5) |y| st[5 * y + x] ^= d;
        }

        var last = st[1];
        comptime var rotation = 0;
        inline for (pi, 1..) |x, i| {
            rotation = (rotation + i) % 64;
            const next = st[x];
            st[x] = math.rotl(Lanes, last, rotation);
            last = next;
        }

        inline for (0..5) |y| {
            const row = st[5 * y ..][0..5];
            t = row.*;
            inline for (row, 0..) |*lanes, x| {
                lanes.* = t[x] ^ (~t[(x + 1) % 5] & t[(x + 2) % 5]);
            }
        }

        st[0] ^= @splat(round_constant);
    }
}

test {
    _ = @import("tests/flightdeck.zig");
}
