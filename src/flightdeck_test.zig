const std = @import("std");
const crypto = std.crypto;
const math = std.math;
const mem = std.mem;
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
const TurboShake128Bo = flightdeck.TurboShake128Bo;
const TurboShake256Bo = flightdeck.TurboShake256Bo;

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

// A duplex cipher that asks for up to `parallelism` clones at once, whatever the target.
fn WithParallelism(comptime Duplex: type, comptime parallelism_: comptime_int) type {
    return struct {
        const Self = @This();

        pub const block_length = Duplex.block_length;
        pub const key_length = Duplex.key_length;
        pub const key_length_min = Duplex.key_length_min;
        pub const key_length_max = Duplex.key_length_max;
        pub const Trailer = Duplex.Trailer;
        pub const parallelism = parallelism_;

        d: Duplex,

        pub fn init(key: []const u8) Self {
            return .{ .d = .init(key) };
        }

        pub fn cloneCompact(self: *const Self) Self {
            return .{ .d = self.d.cloneCompact() };
        }

        pub fn duplex(self: *Self, out: []u8, in: []const u8, trailer: Trailer) void {
            self.d.duplex(out, in, trailer);
        }

        pub fn squeeze(self: *Self, out: []u8) void {
            self.d.squeeze(out);
        }

        pub fn xor(self: *Self, out: []u8, in: []const u8) void {
            self.d.xor(out, in);
        }

        pub fn Parallel(comptime n: comptime_int) type {
            return struct {
                const Clones = @This();

                clones: Duplex.Parallel(n),

                pub fn init(d: *const Self) Clones {
                    return .{ .clones = .init(&d.d) };
                }

                pub fn get(self: *const Clones, i: usize) Self {
                    return .{ .d = self.clones.get(i) };
                }

                pub inline fn duplex(self: *Clones, comptime len: usize, blocks: [n]*const [len]u8, trailer: Trailer) void {
                    self.clones.duplex(len, blocks, trailer);
                }

                pub fn squeeze(self: *const Clones, comptime len: usize, out: *[n * len]u8) void {
                    self.clones.squeeze(len, out);
                }

                pub fn xor(self: *const Clones, comptime len: usize, out: *[n * len]u8, in: *const [n * len]u8) void {
                    self.clones.xor(len, out, in);
                }
            };
        }
    };
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
            const two: u6 = 2;
            self.d.duplex(&.{}, left, e + (two << math.log2_int(u5, e)));
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
    const allocator = testing.allocator;

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
        // Every batch size, including the ones the target wouldn't pick.
        var decks: struct {
            FlightDeck(WithParallelism(Duplex, 1), alpha, c),
            FlightDeck(WithParallelism(Duplex, 2), alpha, c),
            FlightDeck(WithParallelism(Duplex, 4), alpha, c),
            FlightDeck(WithParallelism(Duplex, 8), alpha, c),
        } = .{ .init("key"), .init("key"), .init("key"), .init("key") };

        const in = try allocator.alloc(u8, 18 * alpha + rho + 1);
        defer allocator.free(in);
        for (in, 0..) |*b, i| b.* = @truncate(5 * i + 1);
        var expected: [20 * rho]u8 = undefined;
        var out: [expected.len]u8 = undefined;

        var prng: std.Random.DefaultPrng = .init(testing.random_seed);
        const random = prng.random();

        // Lengths around every multiple of half a chunk, where the way chunks are batched changes.
        for (0..37) |half_chunks| {
            for ([_]usize{ 0, 1, 2, rho + 1, rho + 2 }) |extra| {
                const x = in[0..half_chunks * alpha / 2 + extra -| 1];
                const trailer = random.intRangeAtMost(u5, 1, 31);
                const z = out[0..random.uintAtMost(usize, out.len)];
                const second = random.uintAtMost(usize, z.len);
                const first = random.uintAtMost(usize, second);

                try reference.duplexing(allocator, expected[0..z.len], x, trailer);
                // The same output, in three pieces.
                inline for (&decks) |*deck| {
                    deck.duplex(z[0..first], x, trailer);
                    deck.squeeze(z[first..second]);
                    deck.squeeze(z[second..]);
                    try testing.expectEqualSlices(u8, expected[0..z.len], z);
                }
            }
        }
    }
}

test "DeckBo test vectors" {
    const Vectors = struct {
        // Ciphertext and tag of each message of a session.
        session: [4][]const u8,
        // End of the ciphertext of a long message, and its tag.
        long_ciphertext: *const [64:0]u8,
        long_tag: *const [64:0]u8,
    };
    // Generated with XKCP.
    const vectors = [_]Vectors{
        .{
            .session = .{
                "1c106e7483215251a6d39d1b7ced5081",
                "a1ee10ab51029ad2520e746fa3616d10",
                "c0e75ee6dbd1815bace517f6e80e78c4fe8de69c68",
                "fd79fad9b021cf4e7d5e2f8a45a5fec28b5d267ff026b830e3636a05424870a0589dc31a036457f4b2ffa678aeb4742fcd8b280e257586cc",
            },
            .long_ciphertext = "448ad0859b25d898a569dbc54e9f10a7845a2085334be423dd62081236ef3477",
            .long_tag = "bfea226043c96f981d2a87ec6b595fd7517fca51190b24c87aaa4b4f46285baf",
        },
        .{
            .session = .{
                "50a6969d91e4a3cf6cbab92862e5331d",
                "50ca4c773b1fae7dd184da8e1a57cb11",
                "aaa5df8bcbfdc6e371c38b184644023fe70204d650",
                "f045a1839d595957f5719040ee4ede0d6739e3661ff96bba0115410180fb8429c3b39f2085e9192d5b82af48bbc2ebc63f552116f9d440ff",
            },
            .long_ciphertext = "8f73baf8369dbd41a3b5d2d90952d136150794452602586aeb99e98c4af29c20",
            .long_tag = "e531fa17ca00de8db462ddfe079be91e2e55d0b06ea72932f7ecffe19255c3aa",
        },
    };

    inline for (.{ TurboShake128Bo, TurboShake256Bo }, vectors) |Aead, expected| {
        var key: [32]u8 = undefined;
        for (&key, 0..) |*b, i| b.* = @intCast(i);

        // Four messages, with and without associated data and plaintext.
        var sender: Aead(16) = .init(key[0..16]);
        var receiver = sender;
        inline for (.{ 0, 5, 0, 7 }, .{ 0, 0, 5, 40 }, expected.session, 0..) |ad_len, m_len, hex, i| {
            var ad: [ad_len]u8 = undefined;
            var m: [m_len]u8 = undefined;
            fillPattern(&ad, 1, 17 * i);
            fillPattern(&m, 3, 29 * i);

            var c: [m_len]u8 = undefined;
            var tag: [16]u8 = undefined;
            sender.encrypt(&c, &tag, &m, &ad);
            var c_and_tag: [m_len + 16]u8 = undefined;
            _ = try std.fmt.hexToBytes(&c_and_tag, hex);
            try testing.expectEqualSlices(u8, &c_and_tag, &(c ++ tag));

            var decrypted: [m_len]u8 = undefined;
            try receiver.decrypt(&decrypted, &c, tag, &ad);
            try testing.expectEqualSlices(u8, &m, &decrypted);
        }

        // Many chunks of associated data and of plaintext, encrypted and decrypted in place.
        var ad: [20000]u8 = undefined;
        var m: [80000]u8 = undefined;
        fillPattern(&ad, 1, 0);
        fillPattern(&m, 3, 0);
        var aead: Aead(32) = .init(&key);
        const fresh = aead;
        var tag: [32]u8 = undefined;
        aead.encrypt(&m, &tag, &m, &ad);

        var c_end: [32]u8 = undefined;
        var long_tag: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&c_end, expected.long_ciphertext);
        _ = try std.fmt.hexToBytes(&long_tag, expected.long_tag);
        try testing.expectEqualSlices(u8, &c_end, m[m.len - 32 ..]);
        try testing.expectEqualSlices(u8, &long_tag, &tag);

        aead = fresh;
        try aead.decrypt(&m, &m, tag, &ad);
        var plaintext: [m.len]u8 = undefined;
        fillPattern(&plaintext, 3, 0);
        try testing.expectEqualSlices(u8, &plaintext, &m);
    }
}

test "DeckBo authentication failure" {
    const Aead = TurboShake128Bo(16);
    const m = "a message";
    const ad = "associated data";

    var sender: Aead = .init("key");
    var receiver = sender;
    var c: [m.len]u8 = undefined;
    var tag: [Aead.tag_length]u8 = undefined;
    sender.encrypt(&c, &tag, m, ad);

    var out: [m.len]u8 = undefined;
    var bad_tag = tag;
    bad_tag[0] ^= 1;
    try testing.expectError(error.AuthenticationFailed, receiver.decrypt(&out, &c, bad_tag, ad));
    try testing.expect(mem.allEqual(u8, &out, 0));
    var bad_c = c;
    bad_c[0] ^= 1;
    try testing.expectError(error.AuthenticationFailed, receiver.decrypt(&out, &bad_c, tag, ad));
    try testing.expectError(error.AuthenticationFailed, receiver.decrypt(&out, &c, tag, "other data"));

    // The session didn't move: the message is still accepted, but only once.
    try receiver.decrypt(&out, &c, tag, ad);
    try testing.expectEqualSlices(u8, m, &out);
    try testing.expectError(error.AuthenticationFailed, receiver.decrypt(&out, &c, tag, ad));
}
