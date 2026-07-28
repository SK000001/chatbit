# chatbit

Encrypted mesh chat over radio you control.

Same shape as [bitchat](https://github.com/permissionlesstech/bitchat) — no servers, no
accounts, no phone numbers, messages flooded hop to hop between nearby devices — but
the link layer is a LoRa radio instead of Bluetooth LE, so **the frequency, spreading
factor, bandwidth and transmit power are yours to set**, and the crypto is built to fail
better under the attacks that were actually reported against bitchat.

```
alice ((( ~~~ ))) bob ((( ~~~ ))) carol
      868.1 MHz         868.1 MHz

  bob relays alice's traffic to carol without being able to read it,
  without learning who sent it, and without learning who it was for.
```

---

## First, the question you asked: how secure is bitchat?

bitchat launched in July 2025 and the security story went badly, in a way worth
understanding before building anything similar.

**What it got right.** The architecture is sound: BLE mesh with controlled flooding,
no servers, no identifiers, ephemeral peer IDs. Current versions use
`Noise_XX_25519_ChaChaPoly_SHA256` — a real, analysed protocol from the
[Noise framework](https://noiseprotocol.org/), giving mutual authentication and
forward secrecy. Relays see only opaque ciphertext. That is a good design.

**What went wrong.** The first release shipped hand-rolled crypto with no external
review. Security researcher Alex Radocea demonstrated a working man-in-the-middle
impersonation attack: the identity keys backing the "Favorites" system weren't properly
bound to the session doing the talking, so an attacker could interpose and be treated as
a trusted contact. A separate buffer-overflow report followed. The initial GitHub issue
was closed as "completed" without a real fix. Jack Dorsey subsequently
[acknowledged](https://techcrunch.com/2025/07/09/jack-dorsey-says-his-secure-new-bitchat-app-has-not-been-tested-for-security)
that the app had never had a security review and added a warning to that effect.

Trail of Bits' [write-up](https://blog.trailofbits.com/2025/07/18/building-secure-messaging-is-hard-a-nuanced-take-on-the-bitchat-security-debate/)
is the fairest reading: building secure messaging is genuinely hard, and shipping
"secure" in your README before anyone has looked at your protocol is the actual mistake.

**The transferable lesson:** the primitives were never the weak point. Curve25519 and
AES-GCM are fine. The weak point was *how identity was bound to a session* — and that is
protocol design, which is where nearly all real messenger bugs live.

So chatbit is built on that lesson. Every design note below traces back to it.

---

## What chatbit does differently

| | bitchat | chatbit |
|---|---|---|
| Link | Bluetooth LE (2.4 GHz, fixed) | LoRa — **you pick frequency, SF, BW, power** |
| Range | ~10–100 m per hop | ~2–15 km per hop |
| Handshake | Noise XX | Noise XX |
| Identity binding | *was* the reported weak point | Ed25519 signature over the **live handshake transcript** |
| After the handshake | Noise transport keys | **Double Ratchet** — adds post-compromise security |
| Key change for a known peer | — | **Hard abort**, never a silent re-pin |
| Frame length | "fixed-size where possible" | **Strict padding** — every frame identical on air |
| Recipient addressing | peer ID | **Rotating epoch tags** — no stable address on the wire |
| Cover traffic | — | Optional chaff, indistinguishable from real frames |
| Regulatory limits | n/a | Band plans and duty cycle **enforced in the TX path** |

### The four things that matter most

**1. Identity is bound to the transcript.** The handshake payload carries
`ed25519_pub || sig(DOMAIN || h)`, where `h` is the Noise transcript hash at that exact
point — committing to both ephemerals and both static keys. A signature cannot be lifted
from one session into another, and a relay cannot swap in its own static key while keeping
someone else's identity. A handshake without a valid signature is **aborted**, not
downgraded to "unverified". This is the direct fix for the bitchat impersonation class.

**2. Sessions heal after compromise.** Noise XX gives forward secrecy: keys derived today
don't open yesterday's traffic. It does not give *post-compromise* security — seize a
device and every future message in that session is readable forever. For a protocol whose
premise is operating where devices get seized, that's the wrong failure mode. chatbit
seeds a Double Ratchet from the handshake, so an attacker who steals your state loses
access again after two round trips. ([Tested](tests/test_security.py).)

**3. Names are not identities.** Peers are keyed by public key. Nicknames are display
data and never used for lookup or authorisation — `by_nickname()` returns a *list*,
because nicknames are not unique and pretending otherwise is how impersonation gets easy.
A known peer presenting a different key raises `KeyChangedError` and the session is
refused until you re-verify out of band.

**4. Metadata is treated as a real threat.** Encrypting content while broadcasting a
stable recipient address means anyone with a receiver can build your contact graph
without breaking any crypto. chatbit puts no sender in the header at all, and addresses
frames with an epoch-keyed HMAC tag that rotates on its own and is meaningless to
everyone but the recipient.

---

## Try it without hardware

```bash
git clone https://github.com/sk000001/chatbit && cd chatbit
python3 -m venv .venv && .venv/bin/pip install -e .

.venv/bin/chatbit demo --nodes 4
```

Four nodes in a line, only neighbours in range. Watch a handshake cross three hops and a
message reach the far end while the relays report seeing zero plaintext:

```
node0    relayed   2  received   5  delivered locally   2  plaintext seen: 0
node1    relayed   5  received  10  delivered locally   3  plaintext seen: 0
node2    relayed   5  received  10  delivered locally   3  plaintext seen: 0
node3    relayed   3  received   5  delivered locally   3  plaintext seen: 1
```

Then chat between two terminals over UDP multicast — same protocol, no radio:

```bash
.venv/bin/chatbit --nick alice chat --transport udp
.venv/bin/chatbit --nick bob   chat --transport udp
```

## Check your radio budget before you buy anything

LoRa's range is bought with time on air, and time on air is exactly what regulators cap.
`chatbit plan` tells you what a configuration actually costs:

```bash
.venv/bin/chatbit plan --region EU868 --sf 9
```

```
868.100 MHz  SF9  BW125k  CR4/5  14 dBm  [EU868]
  1758 bit/s nominal, 1005 ms per 200-byte frame

padding policy: strict
  a one-line message occupies 200 B on air, 1005 ms
  duty cycle 1% forces a 100 s gap between frames -> about 35 frames/hour
  a handshake is ~5 frames, so roughly 8.4 min to establish a session

  WARNING: STRICT padding pads every frame to the full MTU, which is what makes
  message length unobservable -- but it is expensive here.
    You get ~35 frames/hour. Consider --padding bucket, a lower SF, or a region
    without a duty cycle.
```

**Read that warning.** It is the central trade-off of this project and it is not
hypothetical. Full length-hiding on a duty-cycle-limited band costs you most of your
message rate. `--padding bucket` and `--sf 7` buy most of it back for a modest leak.
Run `chatbit plan` for your own region before committing.

`plan` also catches the case where a config is simply illegal — SF9 at 200 bytes is
~1005 ms on air, well over the FCC's 400 ms dwell limit, so that default is unusable on
US915 and the tool says so instead of letting you find out from a letter.

## With real hardware

Any serial-attached LoRa module. Reyax RYLR896/RYLR998 work out of the box (~$10, no
soldering); anything running SLIP-framed firmware works too and gets the full 255-byte
payload. See [docs/firmware.md](docs/firmware.md).

```bash
pip install pyserial

.venv/bin/chatbit --nick alice chat \
    --transport lora --port /dev/ttyUSB0 \
    --region EU868 --freq 868.1 --sf 7 --bw 125 --power 14
```

Exchange static keys out of band (`chatbit id` prints yours), then `/connect <hexkey>`.

## Verify your peers

TOFU pinning is only as good as the one-time check. After a handshake:

```bash
.venv/bin/chatbit peers --verify a3f9
```

Prints a 60-digit safety number both sides compute identically. Compare it over a channel
you already trust — in person, or a voice call where you recognise the voice. A
man-in-the-middle can complete handshakes with both of you, but
[cannot make the two numbers match](tests/test_security.py).

---

## How it fits together

```
  cli.py                       node.py                     session.py
  ├─ chat / demo / plan        ├─ beacons, cover traffic   ├─ Noise XX handshake
  └─ peers --verify            └─ fragment → pad → send    ├─ identity binding + pinning
                                        │                  └─ Double Ratchet sessions
                              mesh/router.py
                              ├─ flood, dedup, TTL         crypto/
                              ├─ jittered relay            ├─ noise.py    Noise_XX_25519_ChaChaPoly_SHA256
                              └─ store-and-forward         ├─ ratchet.py  Double Ratchet
                                        │                  ├─ identity.py Ed25519 + TOFU trust store
                              wire/                        └─ primitives.py
                              ├─ packet.py   23-byte header
                              ├─ tags.py     rotating recipient tags
                              ├─ fragment.py LoRa MTU splitting
                              └─ padding.py  length hiding
                                        │
                              radio/  ← swap the link, protocol unchanged
                              ├─ lora.py     RYLR + SLIP, frequency control
                              ├─ udp.py      multicast, for development
                              ├─ loopback.py in-process, for tests
                              ├─ airtime.py  time-on-air + duty cycle governor
                              └─ regions.py  band plans
```

Crypto suite: X25519 · Ed25519 · ChaCha20-Poly1305 · SHA-256 · HKDF. No novel
constructions anywhere — the interesting parts are standard designs assembled from
standard parts.

## Running it on other platforms

The **protocol** is portable. This **implementation** is not — it needs CPython and a
serial-attached LoRa radio, which rules out phones on both counts. No phone has a LoRa
radio, so a mobile build talks to an external board over BLE, the way
[Meshtastic](https://meshtastic.org/docs/faq/) does. (Bluetooth comes back — not as the
mesh, but as the tether.)

So the portability layer is a spec plus test vectors rather than a cross-platform binary:

| | |
|---|---|
| [`docs/PROTOCOL.md`](docs/PROTOCOL.md) | Complete language-agnostic spec. Everything needed to implement chatbit without reading the Python. |
| [`docs/PORTING.md`](docs/PORTING.md) | How to port safely, in dependency order, and the mistakes to avoid. |
| [`vectors/`](vectors/) | Machine-readable vectors pinning every intermediate value. |

```bash
.venv/bin/python tools/verify_vectors.py     # 166 conformance checks
.venv/bin/python tools/generate_vectors.py   # regenerate (deterministic)
```

The vectors matter more than usual here. bitchat's bug was not a broken primitive — it
was how identity bound to a session, which is invisible to any test that only checks
"can Alice message Bob". Reimplementing a handshake and a ratchet by eye, in a new
language, with no way to inspect intermediate state, is how that gets reintroduced. So
the vectors pin `h` and `ck` after *every* handshake message, the full ratchet chain
including DH steps and out-of-order delivery, and nonce counters at 2³² and 2³⁹ that
catch endianness errors the usual n=0/n=1 cases sail straight past.

## Tests

```bash
.venv/bin/python -m pytest -q      # 88 tests
```

The ones worth reading are in [`tests/test_security.py`](tests/test_security.py): MITM
detection, forged-signature rejection, replayed identity proofs, key-change refusal,
forward secrecy, post-compromise healing, and bounded state under flooding.

[`tests/test_vectors.py`](tests/test_vectors.py) guards against protocol drift — any
change to a derivation, domain string or wire offset fails until the vectors are
regenerated deliberately. Once a second implementation exists, that is a version bump
rather than a routine diff.

CI runs the suite on Linux, macOS and Windows across Python 3.10–3.13.

---

## Before you transmit

**Encryption on amateur radio bands is prohibited** in most jurisdictions — in the US,
FCC Part 97.113(a)(4) bans messages "encoded for the purpose of obscuring their meaning".
That is precisely what this is. Ham bands would give you much better range and you may
not use them for this.

Use licence-exempt ISM spectrum: EU868, EU433, US915, AS923, AU915, IN865, KR920, CN470,
or 2.4 GHz. `chatbit regions` lists them with their limits, and those limits are enforced
in the transmit path rather than left to your good intentions. Selecting a region asserts
that you're entitled to use it — the software cannot tell where you are.

## Status

**Unaudited.** No external security review. That is the same disclosure bitchat should
have led with, and stating it plainly is the point rather than an afterthought — the
protocol design here is deliberate and tested, but "I wrote tests" is not "a cryptographer
looked at it". Treat this as a well-built experiment. Don't bet your safety on it.

See [SECURITY.md](SECURITY.md) for the full threat model, including what this explicitly
does *not* protect against.

## Sources

- [Jack Dorsey says his 'secure' new Bitchat app has not been tested for security](https://techcrunch.com/2025/07/09/jack-dorsey-says-his-secure-new-bitchat-app-has-not-been-tested-for-security) — TechCrunch
- [Building secure messaging is hard: a nuanced take on the Bitchat security debate](https://blog.trailofbits.com/2025/07/18/building-secure-messaging-is-hard-a-nuanced-take-on-the-bitchat-security-debate/) — Trail of Bits
- [bitchat whitepaper](https://github.com/permissionlesstech/bitchat/blob/main/WHITEPAPER.md)
- [The Noise Protocol Framework](https://noiseprotocol.org/noise.html)
- [The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/) — Signal
