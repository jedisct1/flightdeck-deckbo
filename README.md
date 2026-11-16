# FlightDeck for Zig

FlightDeck is a keyed function that can chew through long inputs and produce long outputs in parallel.
This is a Zig implementation of it.

You also get the two things around it: the overwrite duplex it's built on, and the Deck-BO authenticated encryption mode that goes on top.

It's plain Zig: no dependencies besides the standard library, no assembly.
It uses SIMD wherever your target has it, WebAssembly included.

FlightDeck comes from "Parallelizable modes for duplex-based authenticated encryption" by Joan Daemen, Silvia Mella and Gilles Van Assche.

The overwrite duplex and Deck-BO come from "Shaking up authenticated encryption" by Joan Daemen, Seth Hoffert, Silvia Mella, Gilles Van Assche and Ronny Van Keer.

## What's in there

```text
| Layer             | Types                                                                                              |
|-------------------+----------------------------------------------------------------------------------------------------|
| Duplex cipher     | `Shake128Duplex`, `Shake256Duplex`, `TurboShake128Duplex`, `TurboShake256Duplex`                   |
| Deck cipher       | `Shake128FlightDeck`, `Shake256FlightDeck`, `TurboShake128FlightDeck`, `TurboShake256FlightDeck`   |
| Authenticated enc | `Shake128Bo(tag_length)`, `Shake256Bo(...)`, `TurboShake128Bo(...)`, `TurboShake256Bo(...)`        |
```

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
zig fetch --save git+https://github.com/jedisct1/flightdeck-deckbo
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

## Running the tests

```sh
zig build test     # run the tests
zig build bench    # measure the throughput
```
