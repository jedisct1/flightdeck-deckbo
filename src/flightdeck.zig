//! The overwrite duplex, a duplex cipher that is as secure as (Turbo)SHAKE.
//!
//! https://eprint.iacr.org/2024/1618

const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const math = std.math;
const KeccakF = crypto.core.keccak.KeccakF;

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

/// Append a bit to a trailer.
fn appendBit(trailer: anytype, bit: u1) @Int(.unsigned, @bitSizeOf(@TypeOf(trailer)) + 1) {
    const Extended = @Int(.unsigned, @bitSizeOf(@TypeOf(trailer)) + 1);
    assert(trailer != 0);
    const end = @as(Extended, 1) << math.log2_int(@TypeOf(trailer), trailer);
    return trailer + (end << bit);
}
