const std = @import("std");
const crypto = std.crypto;
const testing = std.testing;

const flightdeck = @import("flightdeck.zig");
const FlightDeck = flightdeck.FlightDeck;
const Shake128Duplex = flightdeck.Shake128Duplex;
const Shake256Duplex = flightdeck.Shake256Duplex;
const TurboShake128Duplex = flightdeck.TurboShake128Duplex;
const TurboShake256Duplex = flightdeck.TurboShake256Duplex;
const Shake128FlightDeck = flightdeck.Shake128FlightDeck;
const Shake256FlightDeck = flightdeck.Shake256FlightDeck;
const TurboShake128FlightDeck = flightdeck.TurboShake128FlightDeck;
const TurboShake256FlightDeck = flightdeck.TurboShake256FlightDeck;

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

test "FlightDeck test vectors" {
    const key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    // Generated with XKCP.
    // The last one has chunks that don't end on a block boundary.
    inline for (.{
        .{ Shake128FlightDeck, 5120, [_]*const [64:0]u8{
            "46522d87bb182c09cb3894f631f0d2038ae9c519ee8a83d9889e9444d9cac055",
            "b8fdbf7c9ce6de5926f483d3727270e8da3e7c4cbe705d11b2aa04a227f531f0",
            "0e2866d9275fa42f13afa406b83dbf5217d3885a53eed1ec27f0fffc8cc38eea",
            "e30f7c5b3cb6c97665159f35d59238a3c1ae808ff381afb2edc77e6a10dc3bd7",
        } },
        .{ Shake256FlightDeck, 8192, [_]*const [64:0]u8{
            "48a3a3e770baa4b4ad1c8433a686033a66274d4b7557e58fefd889c65f6f13d5",
            "a240322bf03fa890d4b9804b574988bd1e224bd2b02e277068fa82ddcbb0ed67",
            "80646d3d6e1af65b3b3aefcc52af92c1ce607b429964d935da5149fe90f46bd6",
            "0de4155a80187d7967547300fe5033e2d2811fde27cfeaf0932e0076000f8b8d",
        } },
        .{ TurboShake128FlightDeck, 5120, [_]*const [64:0]u8{
            "7647c9011410b46aed34896b978d4cf7c6de2a2b02dde9cac3db2d9f0d2d4cd1",
            "42bf0b8604f465b3ed708904287b72af6d38a4b313ff7a43f2d6ebbf08a9ce56",
            "df4abd09ab62f58d3d417cd060c7b1125f12985ad7ff319042633e9685c89f59",
            "ad2ea7d74ee3216ceb8c1e7349aa7affe0a257219bbb8bee2aecc472eace57a1",
        } },
        .{ TurboShake256FlightDeck, 8192, [_]*const [64:0]u8{
            "3f28f4f4ed9df27113e56956de92c68fe0ca4d00c3ebc6201bb6e43079851b52",
            "eda592a2605bfc55d541b14849443c794a13c9d117b7d7da60942374ec8b0cb8",
            "7f5c22615c068bb10c36a2da08b85a07d64a1a2702fb0d1dd98548afba694d5b",
            "8661fa82d4652cfad8e26b7b5b2ecb464035b703b774f35b8bb1b3ba17d4833a",
        } },
        .{ FlightDeck(TurboShake128Duplex, 327, 32), 327, [_]*const [64:0]u8{
            "7647c9011410b46aed34896b978d4cf7c6de2a2b02dde9cac3db2d9f0d2d4cd1",
            "38c74e9d5b7dffaaa5efb0509c559395cf6538994c61afd879c755d47b72ad2c",
            "81f25d44a7e6815d1fa656f37b3847ba687f5af3239a723e785e0c17635aa1df",
            "112e6271871e86acd00f79bde74e30701f6efcdd2b8f11bca27a102d071d50fb",
        } },
    }) |vector| {
        const Deck, const chunk_length, const expected = vector;
        var in: [11 * chunk_length + chunk_length / 2 + 17]u8 = undefined;
        var out: [50000]u8 = undefined;
        var deck: Deck = .init(key);

        // Four calls in a row. The last 32 bytes of each output are checked.
        inline for (
            .{ 0, chunk_length + 1, in.len, 1 },
            .{ 1, 7, 31, 2 },
            .{ 32, 32, 32, out.len },
            expected,
            0..,
        ) |in_len, trailer, out_len, hex, i| {
            fillPattern(in[0..in_len], 1, 17 * i);
            deck.duplex(out[0..out_len], in[0..in_len], trailer);
            var end: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&end, hex);
            try testing.expectEqualSlices(u8, &end, out[out_len - 32 .. out_len]);
        }
    }
}
