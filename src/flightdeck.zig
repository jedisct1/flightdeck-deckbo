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
const builtin = @import("builtin");
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
/// TurboSHAKE128-FlightDeck, a deck cipher with 128 bits of security. About twice as fast as the SHAKE128 one.
pub const TurboShake128FlightDeck = FlightDeck(TurboShake128Duplex, 5120, 32);
/// TurboSHAKE256-FlightDeck, a deck cipher with 256 bits of security. About twice as fast as the SHAKE256 one.
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
/// `padding` is the last byte of a block of the sponge function whose security it matches.
pub fn OverwriteDuplex(comptime security_level: u11, comptime rounds: u5, comptime padding: u8) type {
    comptime assert(security_level > 0 and security_level <= 256 and security_level % 32 == 0);
    comptime assert(rounds > 0 and rounds <= KeccakF(1600).max_rounds);
    comptime assert(padding & 0x80 != 0);

    return struct {
        const Self = @This();

        const Permutation = KeccakF(1600);
        const block_lanes = block_length / 8;
        const permutation_rounds = rounds;
        const sponge_padding = padding;

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

        // Computed once, so that hashing doesn't pay for absorbing an empty key.
        const after_empty_key = after_empty_key: {
            @setEvalBranchQuota(100_000);
            var d: Self = .{};
            d.absorb(&.{}, 0b1);
            break :after_empty_key d.st;
        };

        /// Set the key. Nothing can be squeezed before the first call to `duplex()`.
        pub fn init(key: []const u8) Self {
            assert(key.len <= key_length_max);
            if (key.len == 0) return .{ .st = after_empty_key };
            var self: Self = .{};
            self.absorb(key, 0b1);
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
            } else {
                self.st.clear(0, block_length);
                self.st.setBytes(in);
                self.st.addByte(0x01, in.len);
            }
            self.st.st[block_lanes] ^= trailerLane(padding, trailer, in.len == block_length);
            permuteState(rounds, &self.st.st);

            self.st.extractBytes(out);
            self.offset = out.len;
        }

        /// Absorb `in`, of any length, block by block, like calls to `duplex()` that squeeze nothing.
        /// The last block gets `trailer`, the others the empty trailer.
        /// It's faster than calling `duplex()` for each block.
        pub fn absorb(self: *Self, in: []const u8, trailer: Trailer) void {
            const count = if (in.len == 0) 0 else (in.len - 1) / block_length;
            const rest = in[count * block_length ..];
            const last: LastBlocks(1) = .{
                .blocks = .{rest},
                .trailers = .{trailerLane(padding, trailer, rest.len == block_length)},
            };
            absorbBlocks(Self, 1, 25, @ptrCast(&self.st.st), .{in.ptr}, count, &last);
            self.offset = 0;
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
            return ParallelOverwriteDuplex(Self, n);
        }
    };
}

fn ParallelOverwriteDuplex(comptime Duplex: type, comptime n: comptime_int) type {
    comptime assert(math.isPowerOfTwo(n));

    const block_length = Duplex.block_length;
    const block_lanes = Duplex.block_lanes;
    const rounds = Duplex.permutation_rounds;
    const padding = Duplex.sponge_padding;

    return struct {
        const Self = @This();

        /// Lane `i` of every clone. Only the lanes after the block are kept between calls.
        st: [25][n]u64,

        /// Make `n` compact clones of `d`.
        pub fn init(d: *const Duplex) Self {
            var self: Self = undefined;
            for (self.st[block_lanes..], d.st.st[block_lanes..]) |*lanes, lane| lanes.* = @splat(lane);
            return self;
        }

        /// Turn clone `i` into a compact clone of `d`.
        pub fn set(self: *Self, i: usize, d: *const Duplex) void {
            for (self.st[block_lanes..], d.st.st[block_lanes..]) |*lanes, lane| lanes[i] = lane;
        }

        /// Clone `i`, as a compact clone.
        pub fn get(self: *const Self, i: usize) Duplex {
            var d: Duplex = .{};
            for (d.st.st[block_lanes..], self.st[block_lanes..]) |*lane, lanes| lane.* = lanes[i];
            return d;
        }

        /// Make clone `i` absorb `count` full blocks from `blocks[i]`, with the empty trailer.
        /// The clones stay compact.
        pub fn absorb(self: *Self, blocks: [n][]const u8, count: usize) void {
            absorbBlocks(Duplex, n, 0, &self.st, pointers(blocks, count), count, null);
        }

        /// Like `absorb()`, then make clone `i` absorb `last[i]` with `trailers[i]`,
        /// and squeeze `len` bytes from each clone into `out`.
        /// The clones stay compact.
        pub fn duplex(
            self: *Self,
            blocks: [n][]const u8,
            count: usize,
            last: [n][]const u8,
            trailers: [n]Duplex.Trailer,
            comptime len: usize,
            out: *[n][len]u8,
        ) void {
            comptime assert(len <= block_length);
            const out_lanes = @divCeil(len, 8);

            var padded: [n][block_length]u8 = undefined;
            var last_blocks: LastBlocks(n) = undefined;
            for (&last_blocks.blocks, &last_blocks.trailers, &padded, last, trailers) |*block, *lane, *buf, bytes, trailer| {
                assert(bytes.len <= block_length);
                block.* = if (bytes.len == block_length) bytes else padBlock(buf, bytes);
                lane.* = trailerLane(padding, trailer, bytes.len == block_length);
            }
            absorbBlocks(Duplex, n, out_lanes, &self.st, pointers(blocks, count), count, &last_blocks);

            for (out, 0..) |*bytes, i| {
                var lanes: [8 * out_lanes]u8 = undefined;
                inline for (0..out_lanes) |l| mem.writeInt(u64, lanes[8 * l ..][0..8], self.st[l][i], .little);
                bytes.* = lanes[0..len].*;
            }
        }

        /// Make clone `i` of `d` absorb the number `first + i` with `trailer`.
        /// The number is a full block: 8 bytes in little-endian order, then zeros.
        /// Then squeeze a block from each clone into `out`, one after the other.
        /// They're XORed with `in` if there is one, which can be the same buffer as `out`.
        pub fn xorCounters(
            d: *const Duplex,
            first: u64,
            trailer: Duplex.Trailer,
            out: *[n * block_length]u8,
            in: ?*const [n * block_length]u8,
        ) void {
            @setEvalBranchQuota(100_000);
            const V = Lanes(n);

            var counters: [n]u64 = undefined;
            for (&counters, 0..) |*counter, i| counter.* = first + i;
            var a: [25]V = undefined;
            a[0] = fromArray(n, counters);
            inline for (a[1..block_lanes]) |*lanes| lanes.* = splat(V, 0);
            a[block_lanes] = splat(V, d.st.st[block_lanes] ^ trailerLane(padding, trailer, true));
            inline for (a[block_lanes + 1 ..], d.st.st[block_lanes + 1 ..]) |*lanes, lane| lanes.* = splat(V, lane);
            // Out of the loop, the first round gets simpler: most lanes are still zero.
            var c = columnParity(V, &a);
            round(V, &a, &c, round_constants[24 - rounds], laneRange(0, 25), false);
            roundsBetween(V, 25 - rounds, &a, &c);
            round(V, &a, &c, round_constants[23], laneRange(0, block_lanes), true);

            if (n == 1) {
                inline for (a[0..block_lanes], 0..) |lanes, l| {
                    storeLanes(1, 8, toArray(1, lanes), out[8 * l ..][0..8], if (in) |src| src[8 * l ..][0..8] else null);
                }
                return;
            }
            comptime var from = 0;
            inline while (from < block_lanes) : (from += n) {
                const count: comptime_int = @min(n, block_lanes - from);
                var rows: [n]V = @splat(@splat(0));
                rows[0..count].* = a[from..][0..count].*;
                transpose(n, &rows);
                inline for (rows, 0..) |row, i| {
                    const at = i * block_length + 8 * from;
                    storeLanes(n, 8 * count, row, out[at..][0 .. 8 * count], if (in) |src| src[at..][0 .. 8 * count] else null);
                }
            }
        }

        fn pointers(blocks: [n][]const u8, count: usize) [n][*]const u8 {
            var ptrs: [n][*]const u8 = undefined;
            for (&ptrs, blocks) |*ptr, bytes| {
                assert(bytes.len >= count * block_length);
                ptr.* = bytes.ptr;
            }
            return ptrs;
        }
    };
}

/// The FlightDeck deck cipher: like a duplex cipher (see `OverwriteDuplex`), with inputs and outputs of any length.
///
/// `Duplex` is a duplex cipher that looks like `OverwriteDuplex`, including `absorb()`.
/// Its `Parallel()` is optional, and comes with `optimal_parallel_blocks`.
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
        // A single output block also goes through `Parallel()`, which is faster than `duplex()`.
        const output_batch_sizes: []const comptime_int =
            if (@hasDecl(Duplex, "Parallel")) &[_]comptime_int{1} ++ batch_sizes else &.{};
        const blocks_per_chunk = @divCeil(chunk_length, block_length);
        const last_block_length = (chunk_length - 1) % block_length + 1;

        const empty_trailer = 0b1;
        const counter_trailer = 0b10;
        const chaining_value_trailer = 0b100;

        // Room for a batch of chaining values, plus what a flush leaves.
        const root_buffer_length = @max(4096, max_batch_size * chaining_value_length + block_length);

        /// Recommended key length, in bytes.
        pub const key_length = Duplex.key_length;
        /// Minimum key length, in bytes.
        pub const key_length_min = Duplex.key_length_min;
        /// Maximum key length, in bytes.
        pub const key_length_max = Duplex.key_length_max;
        /// A trailer of up to 4 bits, from 1 to 31.
        pub const Trailer = @Int(.unsigned, @bitSizeOf(Duplex.Trailer) - 1);

        d: Duplex,
        /// The output block where the last call stopped, if it wasn't the first one.
        block: [block_length]u8 = undefined,
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
                self.d.absorb(in, last_trailer);
            } else {
                var root: Root = .{ .d = &self.d };
                self.absorbChunks(in, &root);
                self.d.absorb(root.buf[0..root.len], last_trailer);
            }
            self.offset = 0;
            self.output(out, null);
        }

        /// Squeeze more bytes after a call to `duplex()`.
        pub fn squeeze(self: *Self, out: []u8) void {
            self.output(out, null);
        }

        /// Like `squeeze()`, but XOR the output with `in`. They can be the same buffer.
        pub fn xor(self: *Self, out: []u8, in: []const u8) void {
            assert(out.len == in.len);
            self.output(out, in);
        }

        fn output(self: *Self, out: []u8, in: ?[]const u8) void {
            var offset = self.offset.?;
            defer self.offset = offset;
            assert(out.len <= math.maxInt(u64) - offset);

            var i: usize = 0;
            if (offset < block_length) {
                i = @min(block_length - offset, out.len);
                if (in) |src| self.d.xor(out[0..i], src[0..i]) else self.d.squeeze(out[0..i]);
                offset += i;
            }
            const used: usize = @intCast(offset % block_length);
            if (used != 0 and i < out.len) {
                const len = @min(block_length - used, out.len - i);
                xorBytes(out[i..][0..len], if (in) |src| src[i..][0..len] else null, self.block[used..][0..len]);
                offset += len;
                i += len;
            }

            // Block `k`, after the first one, comes from a compact clone that absorbed `k`.
            blocks: while (i < out.len) {
                const left = out.len - i;
                const index = offset / block_length;
                const needed = @divCeil(left, block_length);

                inline for (output_batch_sizes) |n| {
                    if (n >= needed or n == max_batch_size) {
                        const Clones = Duplex.Parallel(n);
                        const batch_length = n * block_length;
                        if (left >= batch_length) {
                            const batch_in = if (in) |src| src[i..][0..batch_length] else null;
                            Clones.xorCounters(&self.d, index, counter_trailer, out[i..][0..batch_length], batch_in);
                            offset += batch_length;
                            i += batch_length;
                        } else {
                            var batch: [batch_length]u8 = undefined;
                            Clones.xorCounters(&self.d, index, counter_trailer, &batch, null);
                            xorBytes(out[i..], if (in) |src| src[i..] else null, batch[0..left]);
                            // Keep an unfinished block for the next call.
                            if (left % block_length != 0) self.block = batch[left - left % block_length ..][0..block_length].*;
                            offset += left;
                            i += left;
                        }
                        continue :blocks;
                    }
                }

                var counter: [block_length]u8 = @splat(0);
                mem.writeInt(u64, counter[0..8], index, .little);
                var clone = self.d.cloneCompact();
                clone.duplex(&self.block, &counter, counter_trailer);
                const len = @min(block_length, left);
                xorBytes(out[i..][0..len], if (in) |src| src[i..][0..len] else null, self.block[0..len]);
                offset += len;
                i += len;
            }
        }

        /// What the main duplex absorbs after its first chunk: the chaining values,
        /// and the end of that chunk if it doesn't end a block.
        /// They wait here to be absorbed many blocks at a time, which is faster.
        const Root = struct {
            d: *Duplex,
            buf: [root_buffer_length]u8 = undefined,
            len: usize = 0,

            fn reserve(self: *Root, len: usize) []u8 {
                if (self.len + len > self.buf.len) {
                    // More bytes follow, so none of these blocks is the last one.
                    const whole = self.len - self.len % block_length;
                    assert(whole != 0);
                    self.d.absorb(self.buf[0..whole], empty_trailer);
                    mem.copyForwards(u8, &self.buf, self.buf[whole..self.len]);
                    self.len -= whole;
                }
                defer self.len += len;
                return self.buf[self.len..][0..len];
            }
        };

        /// Absorb an input longer than a chunk, except the end that is left in `root`.
        /// The first chunk goes to the main duplex, the others to clones of it that each give a chaining value.
        fn absorbChunks(self: *Self, in: []const u8, root: *Root) void {
            const start = self.d.cloneCompact();
            var chunks = in;
            var first = true;

            batches: while (batch_sizes.len != 0) {
                const full = chunks.len / chunk_length;
                if (full + @intFromBool(chunks.len % chunk_length != 0) < 2) break;

                // The narrowest batch that holds the full chunks: a wider one costs more.
                inline for (batch_sizes) |n| {
                    if (n >= full or n == max_batch_size) {
                        chunks = self.absorbBatch(n, chunks, &start, first, root);
                        first = false;
                        continue :batches;
                    }
                }
            }

            if (first) {
                const whole = chunk_length - chunk_length % block_length;
                if (whole != 0) self.d.absorb(chunks[0..whole], empty_trailer);
                @memcpy(root.reserve(chunk_length - whole), chunks[whole..chunk_length]);
                chunks = chunks[chunk_length..];
            }
            while (chunks.len != 0) {
                const chunk = chunks[0..@min(chunk_length, chunks.len)];
                chunks = chunks[chunk.len..];
                var clone = start;
                clone.absorb(chunk, chaining_value_trailer);
                clone.squeeze(root.reserve(chaining_value_length));
            }
        }

        /// Absorb up to `n` full chunks, and the shorter last one if a clone is free.
        /// Returns what's left.
        fn absorbBatch(
            self: *Self,
            comptime n: comptime_int,
            chunks: []const u8,
            start: *const Duplex,
            first: bool,
            root: *Root,
        ) []const u8 {
            const count = @min(chunks.len / chunk_length, n);
            const tail_length = chunks.len - count * chunk_length;
            const joins = count < n and tail_length != 0;

            var clones: Duplex.Parallel(n) = .init(start);
            // Idle clones read the first chunk again, so that every read stays inside the input.
            var blocks: [n][]const u8 = undefined;
            for (&blocks, 0..) |*bytes, i| bytes.* = chunks[if (i < count) i * chunk_length else 0..];
            var before: usize = blocks_per_chunk - 1;

            if (joins) {
                // The shorter chunk starts late, to end with the others.
                const tail_blocks = (tail_length - 1) / block_length;
                const head = before - tail_blocks;
                if (head != 0) {
                    if (count == 1) {
                        // A single chunk is faster outside of a batch.
                        var one = start.*;
                        one.absorb(blocks[0][0 .. head * block_length], empty_trailer);
                        clones.set(0, &one);
                    } else {
                        clones.absorb(blocks, head);
                    }
                    for (&blocks) |*bytes| bytes.* = bytes.*[head * block_length ..];
                    clones.set(count, start);
                }
                blocks[count] = chunks[count * chunk_length ..];
                before = tail_blocks;
            }

            const whole_first_chunk = first and last_block_length == block_length;
            if (first and !whole_first_chunk) {
                // The end of the first chunk goes with the chaining values.
                clones.absorb(blocks, before);
                for (&blocks) |*bytes| bytes.* = bytes.*[before * block_length ..];
                before = 0;
                self.d = clones.get(0);
                @memcpy(root.reserve(last_block_length), blocks[0][0..last_block_length]);
            }

            var last: [n][]const u8 = undefined;
            for (&last, blocks, 0..) |*bytes, chunk, i| {
                const end = chunk[before * block_length ..];
                bytes.* = if (joins and i == count) end else end[0..last_block_length];
            }
            var trailers: [n]Duplex.Trailer = @splat(chaining_value_trailer);
            // More input follows the first chunk, so its last block isn't the last one of the main duplex.
            if (whole_first_chunk) trailers[0] = empty_trailer;

            var cvs: [n][chaining_value_length]u8 = undefined;
            clones.duplex(blocks, before, last, trailers, chaining_value_length, &cvs);
            if (whole_first_chunk) self.d = clones.get(0);

            const from = @intFromBool(first);
            const to = count + @intFromBool(joins);
            @memcpy(root.reserve((to - from) * chaining_value_length), mem.sliceAsBytes(cvs[from..to]));
            return if (joins) chunks[chunks.len..] else chunks[count * chunk_length ..];
        }
    };
}

/// The Deck-BO authenticated encryption mode, on top of a deck cipher such as `FlightDeck`.
///
/// An instance is a session: each message is authenticated along with all the ones before it.
/// There is no nonce, so the same message at the same point of a session gets the same ciphertext.
/// If that's a problem, put a nonce or a counter in the associated data.
///
/// Keep one instance on each side, and call it for every message, in the same order.
/// Encrypting a message and decrypting it leave it in the same state,
/// so one session can carry both directions when the two sides take turns.
/// When they don't, use one session for each direction, each with its own key.
///
/// Between messages, `absorb()` mixes data into the session, and `squeeze()` gets bytes out of it, to make new keys for instance.
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

        /// Mix `data` into the session, without sending anything.
        /// Both sides have to absorb the same data at the same point of the session.
        ///
        /// It's an empty message whose tag is thrown away.
        /// To let the other side check the data, send it the tag of that empty message instead.
        pub fn absorb(self: *Self, data: []const u8) void {
            var tag: [tag_length]u8 = undefined;
            self.encrypt(&.{}, &tag, &.{}, data);
        }

        /// Get bytes that depend on the key and on everything that happened in the session so far.
        /// Both sides get the same ones, so that's how to make new keys out of a session.
        ///
        /// These bytes come after the tag of the last message, and never include it.
        /// Squeezing doesn't move the session: what comes next is the same whether you squeezed or not.
        /// Squeezing again continues where the last call stopped, until the next message or `absorb()`.
        ///
        /// Something has to happen in the session before the first call.
        pub fn squeeze(self: *Self, out: []u8) void {
            self.deck.squeeze(out);
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

/// Append a bit to a trailer.
fn appendBit(trailer: anytype, bit: u1) @Int(.unsigned, @bitSizeOf(@TypeOf(trailer)) + 1) {
    const Extended = @Int(.unsigned, @bitSizeOf(@TypeOf(trailer)) + 1);
    assert(trailer != 0);
    const one: Extended = 1;
    const end = one << math.log2_int(@TypeOf(trailer), trailer);
    return trailer + (end << bit);
}

/// The lane after a block: the trailer, a bit that says if the block was full, and the padding byte.
fn trailerLane(padding: u8, trailer: u6, full: bool) u64 {
    return appendBit(trailer, @intFromBool(full)) | (@as(u64, padding) << 56);
}

/// `bytes`, followed by a 1 bit and zeros up to a whole block, in `buf`.
fn padBlock(buf: anytype, bytes: []const u8) []const u8 {
    const lanes = buf.len / 8;
    buf.* = @splat(0);
    // Copies of a known length don't call memcpy.
    // The last lane is written in one go: bytes written one by one are slow to read back.
    switch (bytes.len / 8) {
        inline 0...lanes - 1 => |whole| buf[0 .. 8 * whole].* = bytes[0 .. 8 * whole].*,
        else => unreachable,
    }
    mem.writeInt(u64, buf[bytes.len - bytes.len % 8 ..][0..8], lastLane(bytes), .little);
    return buf;
}

/// What's left of `bytes` after its last whole lane, followed by a 1 bit.
fn lastLane(bytes: []const u8) u64 {
    const rest = bytes.len % 8;
    const end = @as(u64, 1) << @intCast(8 * rest);
    if (rest == 0) return end;
    if (bytes.len >= 8) return (mem.readInt(u64, bytes[bytes.len - 8 ..][0..8], .little) >> @intCast(64 - 8 * rest)) | end;
    var lane = end;
    for (bytes, 0..) |byte, i| lane |= @as(u64, byte) << @intCast(8 * i);
    return lane;
}

/// `out = in ^ stream`, or `out = stream` without `in`. `out` and `in` can be the same buffer.
fn xorBytes(out: []u8, in: ?[]const u8, stream: []const u8) void {
    const src = in orelse return @memcpy(out, stream);
    // 64-bit words, because vectors of bytes are slow on targets without SIMD.
    const Words = @Vector(4, u64);
    var i: usize = 0;
    while (i + @sizeOf(Words) <= out.len) : (i += @sizeOf(Words)) {
        const x: Words = mem.bytesToValue([4]u64, src[i..][0..@sizeOf(Words)]);
        const k: Words = mem.bytesToValue([4]u64, stream[i..][0..@sizeOf(Words)]);
        out[i..][0..@sizeOf(Words)].* = mem.toBytes(@as([4]u64, x ^ k));
    }
    for (out[i..], src[i..], stream[i..]) |*o, x, k| o.* = x ^ k;
}

/// Store the first `size` bytes of `lanes`, XORed with `in` if there is one.
inline fn storeLanes(comptime n: comptime_int, comptime size: comptime_int, lanes: [n]u64, out: *[size]u8, in: ?*const [size]u8) void {
    const whole = size / 8;
    const rest = size % 8;
    if (whole > 0) {
        const Whole = @Vector(whole, u64);
        var part: Whole = lanes[0..whole].*;
        if (in) |src| part ^= mem.littleToNative(Whole, mem.bytesToValue([whole]u64, src[0 .. 8 * whole]));
        mem.bytesAsValue([whole]u64, out[0 .. 8 * whole]).* = mem.nativeToLittle(Whole, part);
    }
    if (rest != 0) {
        var last: [8]u8 = undefined;
        mem.writeInt(u64, &last, lanes[whole], .little);
        if (in) |src| for (last[0..rest], src[8 * whole ..]) |*b, x| {
            b.* ^= x;
        };
        out[8 * whole ..].* = last[0..rest].*;
    }
}

/// Transpose a square matrix, given as rows.
/// Each shuffle is a single x86 instruction.
/// With `std.simd.interlace()`, the compiler emitted twice as many.
fn transpose(comptime n: comptime_int, rows: *[n]@Vector(n, u64)) void {
    comptime assert(n >= 2 and math.isPowerOfTwo(n));
    const V = @Vector(n, u64);

    if (n > 8) {
        const lanes: [n][n]u64 = rows.*;
        inline for (rows, 0..) |*row, i| {
            var column: [n]u64 = undefined;
            inline for (&column, lanes) |*lane, other| lane.* = other[i];
            row.* = column;
        }
        return;
    }

    // Interleave pairs of rows, even lanes and odd lanes.
    var even: [n / 2]V = undefined;
    var odd: [n / 2]V = undefined;
    inline for (&even, &odd, 0..) |*e, *o, i| {
        e.* = @shuffle(u64, rows[2 * i], rows[2 * i + 1], unpack(n, 0));
        o.* = @shuffle(u64, rows[2 * i], rows[2 * i + 1], unpack(n, 1));
    }
    switch (n) {
        2 => rows.* = .{ even[0], odd[0] },
        4 => rows.* = .{
            @shuffle(u64, even[0], even[1], [4]i32{ 0, 1, ~@as(i32, 0), ~@as(i32, 1) }),
            @shuffle(u64, odd[0], odd[1], [4]i32{ 0, 1, ~@as(i32, 0), ~@as(i32, 1) }),
            @shuffle(u64, even[0], even[1], [4]i32{ 2, 3, ~@as(i32, 2), ~@as(i32, 3) }),
            @shuffle(u64, odd[0], odd[1], [4]i32{ 2, 3, ~@as(i32, 2), ~@as(i32, 3) }),
        },
        8 => {
            // Then move 128-bit pieces into place.
            const low = [8]i32{ 0, 1, 2, 3, ~@as(i32, 0), ~@as(i32, 1), ~@as(i32, 2), ~@as(i32, 3) };
            const high = [8]i32{ 4, 5, 6, 7, ~@as(i32, 4), ~@as(i32, 5), ~@as(i32, 6), ~@as(i32, 7) };
            const evens = [8]i32{ 0, 1, 4, 5, ~@as(i32, 0), ~@as(i32, 1), ~@as(i32, 4), ~@as(i32, 5) };
            const odds = [8]i32{ 2, 3, 6, 7, ~@as(i32, 2), ~@as(i32, 3), ~@as(i32, 6), ~@as(i32, 7) };
            const lanes_02 = .{ @shuffle(u64, even[0], even[1], low), @shuffle(u64, even[2], even[3], low) };
            const lanes_13 = .{ @shuffle(u64, odd[0], odd[1], low), @shuffle(u64, odd[2], odd[3], low) };
            const lanes_46 = .{ @shuffle(u64, even[0], even[1], high), @shuffle(u64, even[2], even[3], high) };
            const lanes_57 = .{ @shuffle(u64, odd[0], odd[1], high), @shuffle(u64, odd[2], odd[3], high) };
            rows.* = .{
                @shuffle(u64, lanes_02[0], lanes_02[1], evens),
                @shuffle(u64, lanes_13[0], lanes_13[1], evens),
                @shuffle(u64, lanes_02[0], lanes_02[1], odds),
                @shuffle(u64, lanes_13[0], lanes_13[1], odds),
                @shuffle(u64, lanes_46[0], lanes_46[1], evens),
                @shuffle(u64, lanes_57[0], lanes_57[1], evens),
                @shuffle(u64, lanes_46[0], lanes_46[1], odds),
                @shuffle(u64, lanes_57[0], lanes_57[1], odds),
            };
        },
        else => unreachable,
    }
}

/// The mask that interleaves the lanes `2k + odd` of two vectors.
fn unpack(comptime n: comptime_int, comptime odd: comptime_int) [n]i32 {
    var mask: [n]i32 = undefined;
    for (0..n / 2) |k| {
        mask[2 * k] = 2 * k + odd;
        mask[2 * k + 1] = ~@as(i32, 2 * k + odd);
    }
    return mask;
}

// With AVX-512, a single state is faster in vector registers, one lane per register.
const one_state_in_vectors = builtin.cpu.arch == .x86_64 and builtin.cpu.has(.x86, .avx512vl);

/// The same lane of `n` states.
/// One state gets the low half of a vector register, or a general register.
fn Lanes(comptime n: comptime_int) type {
    if (n > 1) return @Vector(n, u64);
    return if (one_state_in_vectors) @Vector(2, u64) else u64;
}

inline fn splat(comptime V: type, lane: u64) V {
    return if (V == u64) lane else @splat(lane);
}

inline fn fromArray(comptime n: comptime_int, lanes: [n]u64) Lanes(n) {
    return if (n > 1) lanes else splat(Lanes(1), lanes[0]);
}

inline fn toArray(comptime n: comptime_int, lanes: Lanes(n)) [n]u64 {
    if (n > 1) return lanes;
    return .{if (Lanes(1) == u64) lanes else lanes[0]};
}

/// The last block of each state, and the lane that follows it.
/// With several states, the caller pads the blocks.
fn LastBlocks(comptime n: comptime_int) type {
    return struct { blocks: [n][]const u8, trailers: [n]u64 };
}

/// Make state `i` absorb `count` full blocks from `blocks[i]`, then its block in `last`, if there is one.
/// `st[i]` is lane `i` of every state.
/// Only the lanes after the block are read.
/// After a last block, the first `out_lanes` lanes are written too.
inline fn absorbBlocks(
    comptime Duplex: type,
    comptime n: comptime_int,
    comptime out_lanes: comptime_int,
    st: *[25][n]u64,
    blocks: [n][*]const u8,
    count: usize,
    last: ?*const LastBlocks(n),
) void {
    @setEvalBranchQuota(100_000);
    const block_lanes = Duplex.block_lanes;
    const rounds = Duplex.permutation_rounds;
    const padding = Duplex.sponge_padding;
    const V = Lanes(n);
    const capacity = comptime laneRange(block_lanes, 25);

    var a: [25]V = undefined;
    inline for (a[block_lanes..], st[block_lanes..]) |*lanes, lane| lanes.* = fromArray(n, lane);
    var next = blocks;
    var i: usize = 0;
    while (true) : (i += 1) {
        const is_last = i == count;
        var trailer = splat(V, trailerLane(padding, 0b1, true));
        if (is_last) {
            if (last) |end| {
                trailer = fromArray(n, end.trailers);
                if (n == 1) {
                    loadLastBlock(block_lanes, &a, end.blocks[0]);
                } else {
                    for (&next, end.blocks) |*ptr, bytes| ptr.* = bytes.ptr;
                    loadBlocks(n, block_lanes, &a, next);
                }
            } else break;
        } else {
            loadBlocks(n, block_lanes, &a, next);
        }
        a[block_lanes] ^= trailer;
        var c = permuteAllButLast(V, rounds, &a);
        // Before another block, only the lanes it doesn't overwrite are needed.
        if (is_last) {
            round(V, &a, &c, round_constants[23], capacity | laneRange(0, out_lanes), true);
            inline for (st[0..out_lanes], a[0..out_lanes]) |*lane, lanes| lane.* = toArray(n, lanes);
            break;
        }
        round(V, &a, &c, round_constants[23], capacity, true);
        inline for (&next) |*ptr| ptr.* += 8 * block_lanes;
    }
    inline for (st[block_lanes..], a[block_lanes..]) |*lane, lanes| lane.* = toArray(n, lanes);
}

/// Load the last block of a single state, padded if it's short.
/// It's read in place: a padded copy costs more on WebAssembly.
inline fn loadLastBlock(comptime count: comptime_int, a: *[25]Lanes(1), bytes: []const u8) void {
    const whole = bytes.len / 8;
    const end = lastLane(bytes);
    inline for (a[0..count], 0..) |*lanes, i| {
        const lane = if (i < whole) mem.readInt(u64, bytes[8 * i ..][0..8], .little) else if (i == whole) end else 0;
        lanes.* = splat(Lanes(1), lane);
    }
}

/// Load the first `count` lanes of the block of each state.
inline fn loadBlocks(comptime n: comptime_int, comptime count: comptime_int, a: *[25]Lanes(n), blocks: [n][*]const u8) void {
    @setEvalBranchQuota(100_000);
    if (n == 1) {
        inline for (a[0..count], 0..) |*lanes, i| lanes.* = splat(Lanes(1), mem.readInt(u64, blocks[0][8 * i ..][0..8], .little));
        return;
    }
    // A vector holds the same lane of every state, but a block holds consecutive lanes of one state.
    // So load the blocks as rows, and transpose them.
    comptime var from = 0;
    inline while (from < count) : (from += n) {
        const size: comptime_int = @min(n, count - from);
        var rows: [n]@Vector(n, u64) = undefined;
        inline for (&rows, blocks) |*row, block| {
            var lanes: [n]u64 = @splat(0);
            lanes[0..size].* = mem.littleToNative(@Vector(size, u64), mem.bytesToValue([size]u64, block[8 * from ..][0 .. 8 * size]));
            row.* = lanes;
        }
        transpose(n, &rows);
        a[from..][0..size].* = rows[0..size].*;
    }
}

/// Keccak-p[1600] on a single state.
/// Not inlined, so that every caller shares it.
noinline fn permuteState(comptime rounds: u5, st: *[25]u64) void {
    const V = Lanes(1);
    var a: [25]V = undefined;
    inline for (&a, st) |*lanes, lane| lanes.* = splat(V, lane);
    var c = permuteAllButLast(V, rounds, &a);
    round(V, &a, &c, round_constants[23], laneRange(0, 25), true);
    inline for (st, a) |*lane, lanes| lane.* = toArray(1, lanes)[0];
}

const round_constants = [24]u64{
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
};

/// For each lane of each row after rho and pi: the lane it comes from, and how far that one is rotated.
const rho_pi = [5][5]struct { u5, u6 }{
    .{ .{ 0, 0 }, .{ 6, 44 }, .{ 12, 43 }, .{ 18, 21 }, .{ 24, 14 } },
    .{ .{ 3, 28 }, .{ 9, 20 }, .{ 10, 3 }, .{ 16, 45 }, .{ 22, 61 } },
    .{ .{ 1, 1 }, .{ 7, 6 }, .{ 13, 25 }, .{ 19, 8 }, .{ 20, 18 } },
    .{ .{ 4, 27 }, .{ 5, 36 }, .{ 11, 10 }, .{ 17, 15 }, .{ 23, 56 } },
    .{ .{ 2, 62 }, .{ 8, 55 }, .{ 14, 39 }, .{ 15, 41 }, .{ 21, 2 } },
};

/// The set of lanes from `from` to `to`, `to` excluded.
fn laneRange(comptime from: comptime_int, comptime to: comptime_int) u25 {
    return @truncate((@as(u26, 1) << to) - (@as(u26, 1) << from));
}

/// All the rounds of Keccak-p[1600] but the last one.
/// Returns the parity of the columns for that one.
inline fn permuteAllButLast(comptime V: type, comptime rounds: u5, a: *[25]V) [5]V {
    var c = columnParity(V, a);
    roundsBetween(V, 24 - @as(usize, rounds), a, &c);
    return c;
}

/// Rounds `first` to 22 on the states in `a`.
/// `c` is the parity of their columns, and is kept up to date.
inline fn roundsBetween(comptime V: type, comptime first: usize, a: *[25]V, c: *[5]V) void {
    // The fastest number of rounds per iteration on each target.
    // WebAssembly runtimes slow down a lot with bigger loops of vectors.
    const per_pass = if (builtin.cpu.arch.isWasm()) (if (V == u64) 3 else 1) else 2;
    const looped = (23 - first) / per_pass * per_pass;

    var r: usize = first;
    while (r < first + looped) : (r += per_pass) {
        inline for (0..per_pass) |k| round(V, a, c, round_constants[r + k], laneRange(0, 25), false);
    }
    inline for (first + looped..23) |k| round(V, a, c, round_constants[k], laneRange(0, 25), false);
}

/// One round on the states in `a`, given the parity `c` of their columns.
/// Only the lanes in `keep` are computed, and `c` is updated unless it's the last round.
/// Going row by row was the fastest order, and needs fewer registers.
inline fn round(comptime V: type, a: *[25]V, c: *[5]V, round_constant: u64, comptime keep: u25, comptime last: bool) void {
    @setEvalBranchQuota(100_000);
    var d: [5]V = undefined;
    inline for (.{ 0, 2, 4, 1, 3 }) |x| d[x] = c[(x + 4) % 5] ^ math.rotl(V, c[(x + 1) % 5], 1);
    inline for (0..5) |y| a[5 * y] ^= d[0];

    var e: [25]V = undefined;
    inline for (rho_pi, 0..) |row, y| {
        var b: [5]V = undefined;
        inline for (&b, row) |*lane, source| {
            const from, const rotation = source;
            const t = if (from % 5 == 0) a[from] else a[from] ^ d[from % 5];
            lane.* = math.rotl(V, t, rotation);
        }
        inline for (0..5) |x| e[5 * y + x] = b[x] ^ (~b[(x + 1) % 5] & b[(x + 2) % 5]);
    }
    e[0] ^= splat(V, round_constant);

    inline for (a, e, 0..) |*lane, new, i| {
        if ((keep >> i) & 1 != 0) lane.* = new;
    }
    if (!last) c.* = columnParity(V, a);
}

inline fn columnParity(comptime V: type, a: *const [25]V) [5]V {
    var c: [5]V = undefined;
    inline for (&c, 0..) |*lanes, x| lanes.* = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
    return c;
}

test {
    _ = @import("tests/flightdeck.zig");
}
