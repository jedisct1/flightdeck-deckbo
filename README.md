# FlightDeck for Zig

A Zig implementation of FlightDeck and Deck-BO for encrypting and authenticating data.
Written entirely in Zig, with no dependencies beyond the standard library.

## What's in there

- Duplex cipher: `Shake128Duplex`, `Shake256Duplex`, `TurboShake128Duplex`, `TurboShake256Duplex`.
- Deck cipher: `Shake128FlightDeck`, `Shake256FlightDeck`, `TurboShake128FlightDeck`, `TurboShake256FlightDeck`.
- Authenticated encryption: `Shake128Bo(tag_length)`, `Shake256Bo(...)`, `TurboShake128Bo(...)`, `TurboShake256Bo(...)`.

Not sure which layer you need? Here's what each one does:

- Authenticated encryption is what you want to protect messages.
  You give it a key and a message, and it gives you back a ciphertext nobody can read, plus a tag that proves nobody tampered with it.
  If you just want to encrypt things, pick this one and ignore the rest.
- A deck cipher is the building block underneath.
  It mixes a key with any data you feed it, and gives you back as many random-looking bytes as you ask for.
  That's handy to authenticate data without encrypting it, to derive keys, or to build your own protocol.
- A duplex cipher does the same thing as a deck cipher, but only on small blocks, one at a time.
  The deck cipher is built with it, and unless you're building a mode of your own, you won't need it directly.

The generic constructions behind them are public too: `OverwriteDuplex`, `FlightDeck` and `DeckBo`.

So you can build your own:

- `FlightDeck` takes any duplex type that looks like `OverwriteDuplex`, a chunk length and a chaining value length.
- `DeckBo` takes any deck cipher and a tag length.

And SHAKE or TurboSHAKE?
The TurboSHAKE instances use 12 rounds of Keccak-p[1600] and are about twice as fast as the SHAKE ones, which use 24.
The 128 and 256 in the names are the security levels, in bits.

## Installing

Add the package to your `build.zig.zon`:

```sh
zig fetch --save git+https://github.com/jedisct1/zig-flightdeck
```

Then make the module available to your code, in `build.zig`:

```zig
const flightdeck = b.dependency("flightdeck", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("flightdeck", flightdeck.module("flightdeck"));
```

## Usage

A deck cipher takes strings of any length, and gives you back as many bytes as you want after each of them.
Those bytes depend on the key and on everything it was given so far.

```zig
const flightdeck = @import("flightdeck");

var deck: flightdeck.TurboShake128FlightDeck = .init(key);

// Absorb a string, get 32 bytes that depend on the key and on that string.
var mac: [32]u8 = undefined;
deck.duplex(&mac, message, 1);

// Get more output from the same call.
var more: [1000]u8 = undefined;
deck.squeeze(&more);

// Absorb another string. The output now depends on both strings.
// It can also be XORed into a buffer, to use it as a keystream.
deck.duplex(&.{}, nonce, 1);
deck.xor(ciphertext, plaintext);
```

That last argument of `duplex` is a trailer: a handful of bits you can use for domain separation.

It's an integer made of these bits, least significant first, followed by a final 1.
So `1` is the empty trailer, `0b10` is the single bit 0, and FlightDeck accepts values from 1 to 31.

Need a clone? Just copy the instance.
There's also `cloneCompact()`, which gives you a clone that can only be used to absorb the next string.

One thing to remember: call `duplex` before `squeeze` or `xor`.
There's nothing to squeeze before that, and you'll hit an assertion.

Authenticated encryption works on sessions:

```zig
const Aead = flightdeck.TurboShake128Bo(32);

var sender: Aead = .init(key);
var receiver: Aead = .init(key);

var tag: [Aead.tag_length]u8 = undefined;
sender.encrypt(ciphertext, &tag, message, associated_data);
try receiver.decrypt(decrypted, ciphertext, tag, associated_data);
```

Every message is authenticated along with all the messages that came before it in the session.

There's no nonce. So if you encrypt the same message twice, at the same point of two sessions with the same key, you get the same ciphertext.

Besides the length of the message, that's all it reveals, but if it matters to you, put a nonce or a counter in the associated data.

The tag length is a parameter, in bytes.

A tag of twice the security level, so 32 bytes for the 128-bit instances, also commits to the key, the associated data and the plaintext at that security level.

Keys are normally `key_length` random bytes: 16 for the 128-bit instances and 32 for the 256-bit ones.

That said, any byte string of at most `key_length_max` bytes is accepted, which is 160 and 128 bytes respectively.

## Sessions

A session is a value like any other.
`init()` starts it, everything you encrypt, decrypt or absorb moves it forward, and you keep it around for as long as the conversation lasts, one on each side.

Encrypting a message and decrypting it leave a session in the same state.
So a single session can carry both directions, as long as the two sides take turns:

```zig
const Aead = flightdeck.TurboShake128Bo(16);

var alice: Aead = .init(key);
var bob: Aead = .init(key);

var buffer: [4]u8 = undefined;
var tag: [Aead.tag_length]u8 = undefined;

alice.encrypt(&buffer, &tag, "ping", "");
try bob.decrypt(&buffer, &buffer, tag, "");

bob.encrypt(&buffer, &tag, "pong", "");
try alice.decrypt(&buffer, &buffer, tag, "");
```

If both sides can send whenever they want, their messages can cross and the two sessions stop matching.
In that case, use two sessions, one for each direction, each with its own key. There's an example below.

`absorb()` mixes something into a session without sending a ciphertext: a session identifier, a nonce, the transcript of a handshake.
Both sides have to absorb the same thing at the same point.

`squeeze()` gives you bytes that depend on the key and on everything that happened in the session so far.
Both sides get the same ones, so that's how you make new keys out of a session.

```zig
alice.absorb("session 1234");
bob.absorb("session 1234");

var alice_key: [32]u8 = undefined;
var bob_key: [32]u8 = undefined;
alice.squeeze(&alice_key);
bob.squeeze(&bob_key);
// alice_key and bob_key are the same.
```

All of this happens on the same state, in any order you like: encrypt, decrypt, absorb, squeeze.
The only rule is that the two sides go through the same messages and the same `absorb()` calls, in the same order.

Squeezing is not part of that, because it doesn't move the session: what comes next is the same whether you squeezed or not.
Squeeze again and you get the bytes that follow, not the same ones, until the next message or `absorb()`.
There has to be something in the session first: on a brand new one, `squeeze()` hits an assertion.

An `absorb()` is just an empty message, whose tag is thrown away.
If you'd rather have the other side check what it absorbed, send that tag instead:

```zig
alice.encrypt(&.{}, &tag, &.{}, "session 1234");
try bob.decrypt(&.{}, &.{}, tag, "session 1234");
```

What you squeeze comes after the tag of the last message, and never includes it.
So tags can travel in the clear and squeezed bytes can stay secret.

A few more things to know:

- A message that doesn't authenticate doesn't move the session.
  So a forged or damaged one does no harm: the real one still decrypts after it.
- A message that gets lost or comes out of order is another story: what was sent after it doesn't decrypt until it shows up.
  So sessions need a transport that delivers everything, in order.
- Copying the instance copies the session, to save it or to try something on the side.
- Messages and `absorb()` are Deck-BO as the paper specifies it.
  `squeeze()` is an addition, so don't expect it from other implementations.

Back to the two directions that don't take turns.
Squeeze two keys from a session both sides share, and start one session for each direction.
Here's the client. The server does the same thing with the two keys swapped:

```zig
var keys: [32]u8 = undefined;
handshake.squeeze(&keys);

const client_to_server = keys[0..16];
const server_to_client = keys[16..];
var sending: Aead = .init(client_to_server);
var receiving: Aead = .init(server_to_client);
```

## Hashing

A deck cipher doesn't need a secret key.
With an empty key, it's a hash function:

```zig
var hasher: flightdeck.TurboShake128FlightDeck = .init("");

var digest: [32]u8 = undefined;
hasher.duplex(&digest, message, 1);

// A longer digest? Keep squeezing.
var more: [32]u8 = undefined;
hasher.squeeze(&more);
```

Each call to `duplex()` adds a string, and the digest covers all of them, in order.
There's no way to mix up `"ab"` then `"c"` with `"a"` then `"bc"`, so you can hash a list of fields without length prefixes.

Ask for at least 32 bytes with the 128-bit instances, and 64 bytes with the 256-bit ones.
Finding two inputs with the same digest is then as hard as it is with SHAKE or TurboSHAKE: both papers prove it, even when the key is public.

A public string works as a key too.
Using the name of your application, for instance, keeps its digests apart from everybody else's.

Before you use it that way, know that:

- It's not a standard hash function. The digests don't match TurboSHAKE, KangarooTwelve or anything else, so use those if other software has to compute them.
- The FlightDeck paper mentions hashing without a key as future work.
  If that gets specified some day, the digests may not be the same as the ones you get here.
- Only collisions are covered by a proof.
- Authenticated encryption needs a secret key. Without one, anybody can decrypt.

## Performance

### x86-64, with AVX-512

AMD Ryzen 7 7700 (Zen 4)

| MiB/s   | Code   |  64 B | 1 KiB | 8 KiB | 64 KiB | 1 MiB |
| ------- | ------ | ----: | ----: | ----: | -----: | ----: |
| Hash    | Zig    |   511 |  1377 |  2319 |   4998 |  5951 |
|         | C      |   528 |  1421 |  2347 |   6139 |  6461 |
|         | Rust   |   500 |  1427 |  2302 |   5872 |  6255 |
|         | XKCP   |   176 |   733 |   878 |   2324 |  5139 |
|         | BLAKE3 |   825 |   958 |  4957 |   6345 |  6375 |
| Absorb  | Zig    |   509 |  1374 |  2319 |   4996 |  5951 |
|         | C      |   488 |  1398 |  2343 |   6132 |  6456 |
|         | Rust   |   538 |  1453 |  2315 |   5879 |  6259 |
|         | XKCP   |   175 |   730 |   876 |   2325 |  5138 |
|         | BLAKE3 |   821 |   956 |  4952 |   6341 |  6381 |
| Squeeze | Zig    |   511 |  2933 |  5531 |   6093 |  6160 |
|         | C      |   496 |  2788 |  5360 |   5972 |  6070 |
|         | Rust   |   529 |  2407 |  5045 |   6114 |  6181 |
|         | XKCP   |   176 |   825 |  3803 |   5583 |  5792 |
|         | BLAKE3 |   816 |  5823 |  6654 |   6736 |  6728 |
| Deck-BO | Zig    |   249 |   934 |  1623 |   2723 |  3009 |
|         | C      |   250 |   936 |  1623 |   2995 |  3092 |
|         | Rust   |   276 |   906 |  1575 |   2944 |  3073 |
|         | XKCP   |    86 |   381 |   707 |   1634 |  2696 |

### WebAssembly, Wasmer with Cranelift

| MiB/s   | Code   |  64 B | 1 KiB | 8 KiB | 64 KiB | 1 MiB |
| ------- | ------ | ----: | ----: | ----: | -----: | ----: |
| Hash    | Zig    |   270 |   763 |  1191 |   1362 |  1409 |
|         | C      |   207 |   647 |   717 |    741 |   741 |
|         | Rust   |   268 |   707 |  1023 |   1342 |  1413 |
|         | XKCP   |   162 |   503 |   717 |    778 |   782 |
|         | BLAKE3 |   657 |   781 |  1719 |   1749 |  1747 |
| Absorb  | Zig    |   208 |   771 |  1188 |   1361 |  1410 |
|         | C      |   226 |   660 |   719 |    740 |   741 |
|         | Rust   |   274 |   696 |  1030 |   1342 |  1410 |
|         | XKCP   |   159 |   505 |   717 |    778 |   785 |
|         | BLAKE3 |   662 |   790 |  1719 |   1749 |  1746 |
| Squeeze | Zig    |   281 |  1105 |  1463 |   1584 |  1595 |
|         | C      |   230 |   563 |   615 |    626 |   624 |
|         | Rust   |   268 |   948 |  1352 |   1454 |  1453 |
|         | XKCP   |   165 |   376 |   403 |    410 |   411 |
|         | BLAKE3 |   547 |   717 |   730 |    731 |   731 |
| Deck-BO | Zig    |   127 |   446 |   642 |    727 |   743 |
|         | C      |   122 |   306 |   331 |    339 |   339 |
|         | Rust   |   143 |   402 |   570 |    690 |   710 |
|         | XKCP   |    85 |   213 |   265 |    278 |   279 |

### WebAssembly, Wasmer with LLVM

| MiB/s   | Code   |  64 B | 1 KiB | 8 KiB | 64 KiB | 1 MiB |
| ------- | ------ | ----: | ----: | ----: | -----: | ----: |
| Hash    | Zig    |   328 |   945 |   917 |    932 |   926 |
|         | C      |   364 |  1054 |  1113 |   1179 |  1185 |
|         | Rust   |   315 |   803 |   734 |    962 |   972 |
|         | XKCP   |   292 |   820 |  1045 |   1081 |  1079 |
|         | BLAKE3 |   665 |   909 |  2288 |   2346 |  2353 |
| Absorb  | Zig    |   323 |   942 |   917 |    932 |   926 |
|         | C      |   329 |  1034 |  1110 |   1179 |  1185 |
|         | Rust   |   323 |   823 |   734 |    964 |   973 |
|         | XKCP   |   290 |   822 |  1043 |   1076 |  1079 |
|         | BLAKE3 |   657 |   908 |  2288 |   2345 |  2351 |
| Squeeze | Zig    |   333 |   831 |   917 |    938 |   938 |
|         | C      |   328 |   823 |   902 |    913 |   911 |
|         | Rust   |   317 |   822 |   958 |    977 |   977 |
|         | XKCP   |   294 |   711 |   775 |    787 |   785 |
|         | BLAKE3 |   675 |  1059 |  1092 |   1099 |  1097 |
| Deck-BO | Zig    |   164 |   437 |   455 |    466 |   465 |
|         | C      |   176 |   451 |   497 |    502 |   501 |
|         | Rust   |   168 |   410 |   414 |    484 |   486 |
|         | XKCP   |   152 |   373 |   441 |    453 |   452 |

## References

FlightDeck comes from ["Parallelizable modes for duplex-based authenticated encryption"](https://eprint.iacr.org/2026/2801) by Joan Daemen, Silvia Mella and Gilles Van Assche.

The overwrite duplex and Deck-BO come from ["Shaking up authenticated encryption"](https://eprint.iacr.org/2024/1618) by Joan Daemen, Seth Hoffert, Silvia Mella, Gilles Van Assche and Ronny Van Keer.
