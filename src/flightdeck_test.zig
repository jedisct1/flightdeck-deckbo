const std = @import("std");
const crypto = std.crypto;
const testing = std.testing;

const flightdeck = @import("flightdeck.zig");
const Shake128Duplex = flightdeck.Shake128Duplex;
const Shake256Duplex = flightdeck.Shake256Duplex;
const TurboShake128Duplex = flightdeck.TurboShake128Duplex;
const TurboShake256Duplex = flightdeck.TurboShake256Duplex;

// The inputs of the test vectors.
fn fillPattern(buf: []u8, multiplier: usize, offset: usize) void {
    for (buf, 0..) |*b, i| b.* = @intCast((multiplier * i + offset) % 251);
}

test "OverwriteDuplex against SHAKE and TurboSHAKE" {
    const sha3 = crypto.hash.sha3;

    // A block, and its trailer before and after the duplex appends its bit:
    // 1 for a full block, 0 for a padded one.
    const Call = struct { len: usize, trailer: u6, sponge_trailer: u8 };

    inline for (.{
        .{ Shake128Duplex, sha3.Shake128, false },
        .{ Shake256Duplex, sha3.Shake256, false },
        .{ TurboShake128Duplex, sha3.TurboShake128(null), true },
        .{ TurboShake256Duplex, sha3.TurboShake256(null), true },
    }) |instance| {
        const Duplex, const Xof, const turbo = instance;
        const rho = Duplex.block_length;
        // The first call is the one that absorbs the key.
        const calls = [_]Call{
            .{ .len = 5, .trailer = 1, .sponge_trailer = 0b10 },
            .{ .len = 0, .trailer = 1, .sponge_trailer = 0b10 },
            .{ .len = rho, .trailer = 0b111111, .sponge_trailer = 0b1111111 },
            .{ .len = 1, .trailer = 0b10, .sponge_trailer = 0b100 },
            .{ .len = rho - 1, .trailer = 0b11111, .sponge_trailer = 0b101111 },
            .{ .len = rho, .trailer = 1, .sponge_trailer = 0b11 },
        };

        // What the sponge function has to absorb to return the same thing as the duplex.
        var message: [calls.len * (rho + 8)]u8 = undefined;
        var message_len: usize = 0;
        var expected: [rho]u8 = @splat(0);
        var d: Duplex = undefined;

        for (calls, 0..) |call, i| {
            var block: [rho]u8 = @splat(0);
            fillPattern(block[0..call.len], 3, i);
            const in = block[0..call.len];
            if (call.len < rho) block[call.len] = 0x01;

            // Overwriting the state with a block is like XORing in the block and the previous output.
            for (message[message_len..][0..rho], block, expected) |*m, b, z| m.* = b ^ z;
            message_len += rho;
            var xof: Xof = .init(if (turbo) .{ .delim = call.sponge_trailer } else .{});
            xof.update(message[0..message_len]);
            if (!turbo) xof.update(&.{ call.sponge_trailer, 0, 0, 0, 0, 0, 0 });
            xof.squeeze(&expected);
            message[message_len..][0..8].* = .{ call.sponge_trailer, 0, 0, 0, 0, 0, 0, if (turbo) 0x80 else 0x9f };
            message_len += 8;

            if (i == 0) {
                d = .init(in);
                continue;
            }
            var out: [rho]u8 = undefined;
            var clone = d.cloneCompact();
            try testing.expectEqual(rho, clone.offset);
            clone.duplex(&out, in, call.trailer);
            try testing.expectEqualSlices(u8, &expected, &out);

            // The same output in three pieces, leaving a byte that the next clone must not get.
            const zeros: [rho]u8 = @splat(0);
            d.duplex(out[0..10], in, call.trailer);
            d.squeeze(out[10..50]);
            d.xor(out[50 .. rho - 1], zeros[50 .. rho - 1]);
            try testing.expectEqualSlices(u8, expected[0 .. rho - 1], out[0 .. rho - 1]);
        }
    }
}
