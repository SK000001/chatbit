# chatbit protocol specification

**Version 1.** Language-agnostic. Everything needed to write an interoperable
implementation in any language is here; the Python in this repository is the
reference, not the definition.

Every construction below has machine-readable test vectors in
[`../vectors/`](../vectors/). If your implementation reproduces those byte for
byte, it will interoperate. Start there — see [PORTING.md](PORTING.md).

Conventions: `||` is concatenation. Byte lengths are in parentheses. **All
multi-byte integers in the frame header are big-endian.** The one exception is
the Noise nonce counter, which is little-endian because the Noise specification
says so — this is the single most common porting bug, and it has dedicated
vectors.

---

## 1. Cryptographic suite

| Role | Algorithm |
|---|---|
| Key agreement | X25519 |
| Signatures | Ed25519 |
| AEAD | ChaCha20-Poly1305 |
| Hash | SHA-256 |
| KDF | HKDF-SHA-256 |
| Password KDF | scrypt (n=2¹⁵, r=8, p=1) |

X25519 **must** reject an all-zero shared secret. A peer that sends a low-order
point can otherwise force a known shared secret.

### 1.1 Noise's HKDF

Noise defines its own expand step. It is **not** HKDF-Expand with an `info`
parameter, and using the standard HKDF here produces a protocol that looks
right and interoperates with nothing:

```
temp_key = HMAC-SHA256(chaining_key, input_key_material)
output1  = HMAC-SHA256(temp_key, 0x01)
output2  = HMAC-SHA256(temp_key, output1 || 0x02)
output3  = HMAC-SHA256(temp_key, output2 || 0x03)
```

Returns the first 2 or 3 outputs as requested. Vectors: `primitives.json` →
`noise_hkdf`.

### 1.2 Noise nonce encoding

```
nonce(n) = 0x00 0x00 0x00 0x00 || uint64_le(n)
```

Four zero bytes, then the counter **little-endian**. Vectors cover n = 0, 1,
2³², 2³⁹ — the first two pass under either byte order, the last two do not.

### 1.3 Domain separation strings

Exact byte strings. A single character off produces different keys.

| Constant | Value |
|---|---|
| Noise protocol name | `Noise_XX_25519_ChaChaPoly_SHA256` |
| Prologue | `chatbit/v1` |
| Identity signature domain | `chatbit/v1 identity-binding` |
| Session KDF info | `chatbit/v1 session` |
| Ratchet root KDF info | `chatbit/v1 ratchet-root` |
| Message key KDF info | `chatbit/v1 message-key` |
| Fingerprint domain | `chatbit/v1 fingerprint` |
| Safety number info | `chatbit/v1 safety-number` |
| Session tag domain | `chatbit/v1 tag` |
| Handshake tag domain | `chatbit/v1 handshake-tag` |

---

## 2. Identity

An identity is two independent keypairs:

- **Ed25519** — signs handshake transcripts. This is the key that *is* you.
- **X25519** — the static key used by the Noise handshake.

They are separate keys, not one converted into the other, so a signing oracle
can never become a key-agreement oracle. They are bound together by the
fingerprint and by the handshake signature.

```
fingerprint = SHA256("chatbit/v1 fingerprint" || ed25519_pub(32) || x25519_pub(32))
short_id    = first 4 bytes of fingerprint, lowercase hex
```

### 2.1 Safety number

The 60-digit value two people compare out of band to detect a
man-in-the-middle.

```
lo, hi = sort([fingerprint_A, fingerprint_B])       # byte-wise ascending
okm    = HKDF-SHA256(ikm = lo || hi, salt = "", info = "chatbit/v1 safety-number", len = 30)
digits = concat(for each byte b in okm: last two digits of the 3-digit decimal form of b)
result = first 60 digits, grouped in fives, space-separated
```

Sorting makes the result order-independent, so both parties compute the same
string. Vectors: `tags_identity.json`.

---

## 3. Handshake — Noise XX

Pattern `XX` from the Noise Protocol Framework, revision 34:

```
-> e
<- e, ee, s, es
-> s, se
```

Standard Noise `CipherState`, `SymmetricState` and `HandshakeState` apply. Two
requirements specific to this protocol:

1. The prologue is `chatbit/v1` and is mixed into `h` before the first message.
2. Each of messages 2 and 3 carries an **identity payload**.

### 3.1 Identity payloads

Message 2 (responder → initiator):

```
ed25519_pub(32) || signature(64) || ratchet_pub(32) || nick_len(1) || nickname(nick_len)
```

Message 3 (initiator → responder):

```
ed25519_pub(32) || signature(64) || nick_len(1) || nickname(nick_len)
```

The signature is:

```
Ed25519_sign(identity_key, "chatbit/v1 identity-binding" || h)
```

where `h` is the Noise transcript hash **at the moment the payload is written,
before it is encrypted**. Both sides can compute this value identically: the
writer captures `h` before `EncryptAndHash(payload)`, the reader captures it
before `DecryptAndHash(payload)`.

`ratchet_pub` in message 2 is a **freshly generated** X25519 public key that
seeds the Double Ratchet. It must not be the responder's static key or its
Noise ephemeral.

### 3.2 Identity binding is mandatory

> This section is the reason the protocol exists in this shape. Implementations
> that treat it as optional are not chatbit.

Because `h` commits to the entire transcript — both ephemerals and both
encrypted static keys — a signature over it cannot be replayed into a different
handshake, and a relay cannot substitute its own static key while keeping
someone else's identity.

An implementation **must**:

- **Abort** the handshake if the signature is missing or does not verify.
  Do not accept the session as "unverified". Do not log a warning and proceed.
- Bind the peer's identity to the `signing_public` key, never to the nickname.
- Treat nicknames as display data with no uniqueness guarantee.

### 3.3 Session key derivation

After the handshake completes, from the final chaining key `ck` and transcript
hash `h`:

```
okm         = HKDF-SHA256(ikm = ck, salt = h, info = "chatbit/v1 session", len = 96)
root_key    = okm[0:32]     # seeds the Double Ratchet
i2r_tag_key = okm[32:64]    # initiator -> responder frame tags
r2i_tag_key = okm[64:96]    # responder -> initiator frame tags
```

Tag keys are directional. The initiator sends with `i2r_tag_key` and recognises
`r2i_tag_key`; the responder is the mirror image.

The Noise `Split()` transport keys are **not** used for application data — the
Double Ratchet replaces them. Implementations may compute them for conformance
checking; the vectors include them.

### 3.4 Trust pinning

On first successful handshake, pin `(signing_public → static_public)`.

On a later handshake, if a pinned `signing_public` presents a **different**
`static_public`, the handshake **must** fail. Re-pinning is an explicit user
action and must clear any verified status. Never re-pin automatically, and do
not offer a "continue anyway" prompt — those get clicked through.

---

## 4. Double Ratchet

Signal's Double Ratchet, revision 1, over X25519 + HKDF-SHA256 +
ChaCha20-Poly1305.

### 4.1 Initialisation

The **initiator** knows the responder's `ratchet_pub` from handshake message 2:

```
DHs      = generate_x25519()
DHr      = responder_ratchet_pub
RK, CKs  = KDF_RK(root_key, DH(DHs, DHr))
CKr      = none;  Ns = Nr = PN = 0
```

The **responder** uses the private half of the ratchet key it published:

```
DHs = its published ratchet keypair
DHr = none;  RK = root_key;  CKs = CKr = none
Ns = Nr = PN = 0
```

The responder has no sending chain until it receives its first message. This
is not an error state, and a vector schedule depends on it.

### 4.2 Key derivation

```
KDF_RK(rk, dh_out):
    okm = HKDF-SHA256(ikm = dh_out, salt = rk, info = "chatbit/v1 ratchet-root", len = 64)
    return okm[0:32] as new root key, okm[32:64] as new chain key

KDF_CK(ck):
    message_key    = HMAC-SHA256(ck, 0x01)
    next_chain_key = HMAC-SHA256(ck, 0x02)

MESSAGE_KEYS(mk):
    okm = HKDF-SHA256(ikm = mk, salt = 32 zero bytes, info = "chatbit/v1 message-key", len = 44)
    return okm[0:32] as AEAD key, okm[32:44] as AEAD nonce
```

### 4.3 Message header

40 bytes, travelling in the clear but authenticated as associated data:

```
ratchet_public(32) || PN(4, big-endian) || N(4, big-endian)
```

### 4.4 Encryption

```
CKs, mk = KDF_CK(CKs)
header  = (DHs.public, PN, Ns)
Ns     += 1
key, nonce = MESSAGE_KEYS(mk)
ciphertext = ChaCha20-Poly1305(key, nonce, plaintext, ad = associated_data || header)
```

Note the associated data: the caller's AD **concatenated with the encoded
header**. Omitting the header lets an attacker rewrite counters undetected.

### 4.5 Decryption — trial-then-commit

> Getting this wrong yields an implementation that works perfectly in testing
> and can be permanently broken by any stranger with a radio.

1. If a stored skipped message key matches `(header.ratchet_public, header.N)`,
   try it. On success, delete the key and return. On failure, raise — but do
   **not** delete the stored key; the real message may still arrive.
2. Otherwise, perform the following **against a copy of the ratchet state**:
   - If `header.ratchet_public != DHr`: skip keys up to `header.PN`, then run
     the DH ratchet step.
   - Skip keys up to `header.N`.
   - Derive the message key and decrypt.
3. **Only if decryption succeeds**, commit the modified state.

Every step above is destructive — advancing a chain key discards the old one.
Since anyone can transmit on an open channel, a forged frame must not be able
to advance state. Commit only after authentication.

### 4.6 DH ratchet step

```
PN  = Ns;  Ns = 0;  Nr = 0
DHr = header.ratchet_public
RK, CKr = KDF_RK(RK, DH(DHs, DHr))
DHs = generate_x25519()
RK, CKs = KDF_RK(RK, DH(DHs, DHr))
```

### 4.7 Bounds

| Limit | Value | Why |
|---|---|---|
| `MAX_SKIP` | 256 | Work a single forged header can force |
| `MAX_SKIPPED_KEYS` | 1024 | Total retained out-of-order keys; evict oldest first |

Exceeding `MAX_SKIP` must reject the message, not clamp and continue.

---

## 5. Frame format

Exactly 23 bytes of header, then payload. All integers big-endian.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 1 | `version` | 1 |
| 1 | 1 | `ptype` | see below |
| 2 | 1 | `ttl` | decremented by each relay |
| 3 | 1 | `frag_index` | 0-based |
| 4 | 1 | `frag_count` | 1 = unfragmented |
| 5 | 8 | `msg_id` | random per logical message; dedup key |
| 13 | 8 | `dst_tag` | rotating recipient tag, or 8 zero bytes for broadcast |
| 21 | 2 | `payload_len` | true length, **excluding** padding |
| 23 | … | `payload` | ciphertext, then padding |

Padding is appended after `payload_len` bytes and is not covered by it, so a
receiver strips it exactly.

### 5.1 Packet types

| Value | Name | Meaning |
|---|---|---|
| `0x01` | `HANDSHAKE_INIT` | Noise message 1 |
| `0x02` | `HANDSHAKE_RESP` | Noise message 2 |
| `0x03` | `HANDSHAKE_FIN` | Noise message 3 |
| `0x10` | `DATA` | ratchet-encrypted application data |
| `0x20` | `BEACON` | signed presence announcement |
| `0x30` | `COVER` | reserved; see §5.2 |
| `0x40` | `ACK` | carried inside `DATA`; not sent bare |

Handshake payloads are prefixed with a 4-byte random `hs_id` used to correlate
the three messages:

```
handshake_payload = hs_id(4) || noise_message
```

### 5.2 Cover traffic

Real cover traffic is sent as `DATA` with a random `dst_tag` and random
payload. It **must not** use packet type `0x30` — an observer would filter it
out of the header in one line, defeating the point. The `COVER` type exists
only for tests and diagnostics.

### 5.3 Validation

A receiver must reject a frame that:

- is shorter than 23 bytes
- has `version != 1`
- has an unknown `ptype`
- has `HEADER_LEN + payload_len > len(frame)` (a lying length field)
- has `frag_index >= frag_count`

---

## 6. Recipient tags

Frames carry no sender field and no stable recipient address. Instead:

```
session_tag(epoch)   = HMAC-SHA256(tag_key, "chatbit/v1 tag" || uint64_be(epoch))[:8]
handshake_tag(epoch) = HMAC-SHA256(responder_static_pub,
                                   "chatbit/v1 handshake-tag" || uint64_be(epoch))[:8]
epoch = floor(unix_time / 600)
```

`EPOCH_SECONDS` is 600. Receivers accept epoch − 1, epoch, and epoch + 1 to
tolerate clock skew, and should compare all candidates without short-circuiting
so timing does not reveal which epoch matched.

Broadcast is 8 zero bytes.

**Known limitation, stated plainly:** handshake tags are keyed by the
responder's static public key, so anyone who already knows that key can detect
that someone is opening a session with that peer. This is a deliberate trade
against the trial-decryption DoS that full anonymity here would cost. Session
tags do not have this property.

---

## 7. Padding

| Policy | Behaviour | Leaks |
|---|---|---|
| `strict` | pad every frame to the link MTU | nothing |
| `bucket` | pad to the next value in the ladder below | ≈ log₂(length) |
| `none` | no padding | exact length |

Bucket ladder: `32, 64, 96, 128, 192, 256, 384, 512, 768, 1024`, clamped to the
MTU.

`strict` is the default. It is also expensive on duty-cycle-limited bands — see
the airtime discussion in the README.

---

## 8. Fragmentation

A logical message longer than `MTU − 23` is split into fragments sharing one
`msg_id`, with ascending `frag_index` and a common `frag_count`. Maximum 255
fragments.

Relays forward fragments individually and never reassemble. Only the
destination reassembles.

Reassembly buffers **must** be bounded on all three axes, because a fragment
flood is the obvious memory attack:

| Bound | Reference value |
|---|---|
| in-flight messages | 64 (evict oldest) |
| bytes per message | 65536 |
| partial message age | 300 s |

Two fragments sharing a `msg_id` but disagreeing on `frag_count` or `ptype`
must discard the whole partial message.

---

## 9. Mesh routing

Controlled flood. No routing tables.

1. On receiving a frame, check `(msg_id, frag_index)` against a dedup cache.
   If present, drop it and cancel any pending relay of the same frame.
2. If the frame is addressed to us, deliver it locally.
3. Decrement TTL. If it reaches 0, stop. Otherwise schedule a relay after a
   random jitter (reference: 50–400 ms).
4. Frames addressed to us are **still relayed** — suppressing them would leak
   which frames were ours to anyone watching relay behaviour.

Reference bounds: dedup cache 4096 entries / 900 s, default TTL 7, max TTL 16.

Jittered relay matters more than it looks on a half-duplex radio: neighbours
that hear a frame simultaneously would otherwise retransmit simultaneously and
collide, and on LoRa each collision costs about a second of airtime.

---

## 10. Beacons

```
body      = ed25519_pub(32) || x25519_pub(32) || timestamp(8, IEEE-754 big-endian double)
payload   = body || Ed25519_sign(identity_key, "chatbit/v1 identity-binding" || body)
            || nick_len(1) || nickname
```

Sent with the broadcast tag.

A beacon proves possession of the identity key. It does **not** prove liveness —
it can be recorded and replayed. Beacons are discovery hints only. All
authentication happens in the handshake. An implementation must never establish
trust from a beacon alone, and must ignore a beacon whose static key conflicts
with a pinned one.

---

## 11. Application messages

Inside the ratchet:

```
kind(1) || timestamp(8, IEEE-754 big-endian double) || body
```

| Kind | Meaning |
|---|---|
| 1 | `TEXT` — body is UTF-8 |
| 2 | `ACK` |
| 3 | `NICK` |

---

## 12. Conformance

An implementation is conformant if `vectors/` reproduces byte for byte and the
following hold. These are the requirements a passing vector run does *not* by
itself prove:

- [ ] Invalid identity signature **aborts** the handshake
- [ ] Changed static key for a pinned identity **aborts** the handshake
- [ ] Nicknames are never used for identity lookup or authorisation
- [ ] Forged frames do not advance ratchet state (trial-then-commit)
- [ ] `MAX_SKIP` is enforced and rejects rather than clamps
- [ ] X25519 rejects all-zero shared secrets
- [ ] Noise nonce counter is little-endian
- [ ] Reassembly buffers are bounded on count, bytes and age
- [ ] Cover traffic is sent as `DATA`, never as type `0x30`
- [ ] Frames addressed to self are still relayed
- [ ] Padding is stripped exactly, never leaking into the payload

---

## 13. Versioning

The frame `version` byte is 1. Any change to a derivation, a domain string, a
wire offset or a padding rule is a new version and requires regenerated
vectors. Implementations must reject frames whose version they do not
implement.
