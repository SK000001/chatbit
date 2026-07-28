# Porting chatbit to another language

The protocol is portable. This Python implementation is not — it needs a
serial-attached LoRa radio and a CPython runtime, which rules out phones on
both counts.

So if you want chatbit on iOS, Android, or anywhere else, you port the
protocol. This document is about doing that without reintroducing the bug class
the design exists to avoid.

## The thing to be careful about

The bitchat impersonation vulnerability was not a broken primitive. Curve25519
and AES-GCM were fine. The bug was in how identity was bound to a session — a
protocol-design mistake, invisible to any test that only checks "can Alice send
Bob a message".

Reimplementing a handshake and a ratchet by eye, in a new language, with no way
to check intermediate state, is how that class of bug gets reintroduced. The
vectors exist so you never have to work blind: they pin every intermediate
value, so a divergence tells you *which operation* went wrong rather than only
that the final keys disagree.

**Port against the vectors, not against the Python.**

## Order of work

Build bottom-up and verify each layer before starting the next. A wrong HKDF
makes everything above it fail in ways that look like handshake bugs.

### 1. Primitives — `vectors/primitives.json`

X25519, Ed25519, ChaCha20-Poly1305, SHA-256, HKDF from your platform's crypto
library. Do not implement these yourself.

Two things are not your platform's defaults and must be written by hand:

- **Noise's HKDF** (`noise_hkdf`) is not HKDF-Expand with an info parameter.
  See PROTOCOL.md §1.1.
- **The Noise nonce** is four zero bytes then the counter **little-endian**.
  The vectors include n = 2³² and n = 2³⁹ precisely because n = 0 and n = 1
  pass under either byte order.

Stop here until every primitive check passes.

### 2. Noise XX — `vectors/noise_xx.json`

Use an existing Noise library if one exists for your language and supports
`Noise_XX_25519_ChaChaPoly_SHA256` with arbitrary handshake payloads. Suitable
options include `noise-java` (southernstorm), `snow` (Rust), `noise-c`, and
Go's `flynn/noise`.

The vector pins both parties' ephemeral private keys, so your handshake is
reproducible. Every implementation needs a seam to inject them — in this
codebase it is `HandshakeState.ephemeral_factory`. Add the equivalent, keep it
test-only, and make sure the production path still generates fresh randomness.

Check `h` and `ck` after **every** message, not just the final keys. That is
what makes a mismatch diagnosable.

Then the part no off-the-shelf Noise library will do for you: the identity
payloads and their signatures (PROTOCOL.md §3.1–3.2). The signed value is
`"chatbit/v1 identity-binding" || h`, where `h` is captured *before* the payload
is encrypted.

### 3. Double Ratchet — `vectors/ratchet.json`

If your language has a vetted Double Ratchet, prefer it — but check the KDF
info strings, which are chatbit-specific and will differ from libsignal's.

The vector's `schedule` array is the operation order. Replay it exactly: sends
and deliveries are interleaved, and the interleaving is load-bearing. A
responder has no sending chain until it has received, so encrypting everything
up front will not even run.

The schedule exercises, in order: three sends on one chain, a direction change
(DH ratchet step), a second chain, and out-of-order delivery that stores and
recovers skipped keys.

**Implement decryption as trial-then-commit** (PROTOCOL.md §4.5). This is the
single most important correctness detail in the ratchet. Advancing a chain key
is destructive, anyone can transmit on an open radio channel, and an
implementation that mutates state before authenticating can be permanently
desynchronised by one forged frame. The reference implementation had exactly
this bug during development; it was caught by
`test_forged_frame_does_not_desynchronise_session`, which you should port too.

### 4. Wire format — `vectors/wire.json`

Mechanical. Watch three things:

- All header integers are **big-endian** (unlike the Noise nonce).
- Padding is appended after `payload_len` bytes and is not covered by it.
  Decoding a padded frame must recover the exact original payload.
- Reject a frame whose `payload_len` runs past the end of the buffer. In a
  memory-unsafe language this is the difference between a dropped frame and a
  remote read primitive.

### 5. Tags and identity — `vectors/tags_identity.json`

Epoch tags, fingerprints, safety numbers. The safety number must be
order-independent — the vector checks both argument orders produce the same
string, because if they do not, two people comparing numbers will never agree
and the MITM defence silently stops working.

### 6. The behavioural checklist

PROTOCOL.md §12. These are the requirements passing vectors does *not* prove,
and they are where the security actually lives. Port the tests in
`tests/test_security.py` alongside them — especially:

- an invalid identity signature aborts, rather than downgrading to unverified
- a changed static key for a pinned identity aborts
- forged frames do not advance ratchet state
- a MITM cannot make both sides' safety numbers agree

## Radio, and what it means on mobile

`radio/` is the only layer that changes for a new platform, because the
protocol above it never learns what carries its bytes.

No phone has a LoRa radio, so a mobile port talks to an external LoRa board.
Bluetooth returns — not as the mesh, but as the tether:

| | Android | iOS |
|---|---|---|
| USB-OTG serial | works | blocked without MFi licensing |
| BLE to a LoRa board | works | works, no MFi needed |

BLE-to-companion-board is the only approach that covers both, and it is what
Meshtastic does. Your transport implements the equivalent of `Transport` in
`chatbit/radio/base.py`: a lossy, unordered, broadcast datagram link with an
MTU. Do not assume more reliability than that even if your link provides it.

Keep the duty-cycle governor. It is in the transmit path rather than advisory
for a reason, and dropping it is how a port ends up transmitting illegally.

## Cross-implementation testing

Once you have a second implementation, the vectors stop being the whole story —
they prove you match a recording, not that two live implementations agree.
Worth adding:

1. **Live interop.** Run a real handshake between implementations over UDP
   multicast, which needs no radio. If both reach the same session keys and
   exchange messages, you are interoperating.
2. **Cross-fuzzing.** Feed each implementation malformed frames and confirm
   both reject the same inputs. Divergence in what gets *rejected* is as
   dangerous as divergence in what gets accepted.

## Changing the protocol

If you need a change, bump the version byte and regenerate the vectors with
`python tools/generate_vectors.py`. `tests/test_vectors.py` fails on any
unintended drift, which is the point — once a second implementation exists, a
regenerated vector file is a protocol version bump, not a routine diff.
