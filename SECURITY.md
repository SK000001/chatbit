# Threat model

**chatbit has not been independently audited.** Nothing below is a guarantee. It is a
description of what the protocol is designed to do, written so that someone competent can
check whether it actually does it — and, more importantly, so you can tell when it does
not apply to your situation.

If your safety depends on this, use [Signal](https://signal.org/). That advice is
sincere, not a disclaimer.

---

## Primitives

| Role | Choice |
|---|---|
| Key agreement | X25519 (rejects low-order points) |
| Signatures | Ed25519 |
| AEAD | ChaCha20-Poly1305 |
| Hash | SHA-256 |
| KDF | HKDF-SHA-256 |
| Handshake | `Noise_XX_25519_ChaChaPoly_SHA256` |
| Message keys | Double Ratchet |
| Password KDF | scrypt (n=2¹⁵, r=8, p=1) |

No custom constructions. Every primitive comes from
[`cryptography`](https://cryptography.io/); the assembled protocols are Noise XX and the
Signal Double Ratchet, both public specifications with published analysis.

---

## What it defends against

### A passive listener with a receiver on your frequency

Sees: that a transmission occurred, its timing, its direction of arrival with the right
equipment, and a fixed-size frame of ciphertext.

Does not see: message content, who sent it (there is no sender field), who it is for
(the destination tag is an epoch-keyed HMAC only the recipient can recognise), or message
length (strict padding makes every frame identical on air).

Cannot link frames across epochs, because destination tags rotate every 10 minutes on
their own.

### A relay node in the mesh

Relays forward ciphertext they cannot decrypt and have no key material for. A relay
learns that traffic passed through it and nothing about its content, source, or
destination. Verified by test: [`test_relay_cannot_read_traffic`](tests/test_e2e.py).

### An active man-in-the-middle

Can complete handshakes with both parties — nothing stops someone from talking to you.
Cannot make the two sides' safety numbers agree, which is what the out-of-band comparison
detects. Verified by test: [`test_mitm_produces_different_safety_numbers`](tests/test_security.py).

**This defence is only real if you actually compare safety numbers.** An unverified
session is marked `UNVERIFIED` everywhere it is displayed, and that label means exactly
what it says.

### An impersonator

This is the bitchat attack class, and it is the one this protocol is most deliberately
built against.

- Identity proofs are Ed25519 signatures over the live Noise transcript hash, so they
  cannot be replayed into another session
  ([`test_signature_from_another_session_is_rejected`](tests/test_security.py)).
- A handshake with a missing or invalid signature is aborted, not accepted as unverified
  ([`test_forged_identity_signature_aborts_handshake`](tests/test_security.py)).
- Peers are keyed by public key; nicknames are never used for lookup or authorisation
  ([`test_nickname_is_never_an_identifier`](tests/test_security.py)).
- A known peer presenting a different key raises `KeyChangedError` and the session is
  refused. Re-pinning is explicit and clears verified status
  ([`test_repin_clears_verification`](tests/test_security.py)).

### Device seizure, after the fact

Forward secrecy: message keys are deleted after use, so current state does not decrypt
previously recorded traffic
([`test_forward_secrecy_current_state_cannot_open_past_messages`](tests/test_security.py)).

Post-compromise security: after a full state compromise the session heals once the DH
ratchet turns — **two round trips**, not instantly. Messages in that window stay readable
to the attacker. This is a property of the Double Ratchet, stated precisely rather than
rounded up
([`test_post_compromise_security_heals_session`](tests/test_security.py)).

### Denial of service against protocol state

Every buffer is bounded, and forged input cannot destroy good state:

- A forged frame cannot desynchronise a live ratchet — decryption is trial-then-commit,
  so state only advances after a message authenticates
  ([`test_forged_frame_does_not_desynchronise_session`](tests/test_security.py)).
- Skipped message keys are capped (256 per chain, 1024 total).
- Pending handshakes are capped at 32 and time out after 120 s.
- The reassembly buffer is bounded by count, bytes, and age.
- The dedup cache is bounded and time-limited.
- Flood amplification is bounded by dedup plus TTL
  ([`test_relay_does_not_storm`](tests/test_e2e.py)).

---

## What it does NOT defend against

Read this section twice. It is the more useful one.

### Traffic analysis of *when* and *where*

Padding hides length. It does not hide that you transmitted, or when. Someone with a
receiver knows a transmission happened. Someone with two receivers can direction-find
you. Someone with several can **locate you to within a few metres**.

This is a property of radio, not of software. It is not fixable at the protocol layer,
and it is the single most likely way this gets someone hurt. Cover traffic
(`--cover`) breaks the correlation between *transmitting* and *having something to say*,
but it does not make you invisible — it makes you continuously visible instead.

**If being located is your threat, do not transmit.**

### Endpoint compromise while it is happening

Malware, a keylogger, a rootkit, or someone reading over your shoulder defeats all of
this. Encryption protects data in transit and nothing else.

### An unverified session

Trust-on-first-use means the *first* contact is unauthenticated. If an attacker is
already in position when you first connect, they are pinned as the legitimate peer.
Safety-number verification is what closes this, and it is a manual step nobody can do for
you.

### Compelled disclosure

Rubber-hose cryptanalysis works. There is no deniability feature, no duress password, and
no plausible-deniability layer.

The identity file **can** be encrypted at rest with scrypt, and the CLI offers this when
creating one — but it is a choice, and declining it writes your private keys to disk in
the clear. `chatbit id` on an existing file tells you which you have. Encryption at rest
resists offline guessing of a stolen file and nothing else: it does not help against a
running process, and it does not help against someone who can make you type the
passphrase.

The passphrase is never accepted as a command-line argument, because argv is readable by
any local user through `ps` and is written to shell history. Use `CHATBIT_PASSPHRASE`, or
let the tool prompt.

**On Windows the file permissions are weaker than on POSIX.** The identity file is
written `0600` on Linux and macOS, but Windows has no POSIX permission bits and
`os.chmod` there only toggles the read-only flag — so the request is a no-op and the file
is left readable by other accounts, protected only by inherited NTFS ACLs. Closing that
properly needs ACL manipulation via pywin32 or `icacls`, which is not implemented. Until
it is, a passphrase is the only real protection for an identity file on Windows, and the
CLI says so when it writes an unencrypted one there.

### Traffic confirmation by a global observer

Someone monitoring the whole radio environment can correlate transmission timing across
the mesh to infer who talks to whom, even without decrypting anything. Cover traffic
raises the cost; it does not eliminate it.

### Metadata leaks specific to this design

Two acknowledged, deliberate ones:

1. **Handshake-initiation tags** are derived from the responder's static public key.
   Anyone who already knows that key can detect that *someone* is opening a session with
   that peer. It leaks only to people who already know who you are, and it avoids the
   trial-decryption DoS that full anonymity here would cost. Session tags, used for all
   subsequent traffic, do not have this property.

2. **Beacons** broadcast your identity key and nickname in the clear, signed. They are
   how discovery works. If you do not want to be discoverable, do not beacon — and be
   aware that a recorded beacon can be replayed, which is why beacons are treated as a
   hint and never as authentication.

### Availability

Jamming works. A sufficiently loud transmitter on your frequency stops the mesh. There is
no frequency hopping, no spread-spectrum evasion, and no anti-jam capability.

### The implementation itself

Python is not constant-time and does not zero memory. Key material stays in the heap and
can land in a swap file or a core dump. `cryptography` handles the primitives in Rust/C,
but the protocol state above it is ordinary Python objects. A memory-forensics attacker
against a running process wins.

---

## Deliberate design decisions

**Trial-then-commit ratchet decryption.** Advancing a ratchet is destructive by design.
On an open radio channel anyone can transmit, so decryption runs against a copy of the
state and commits only on successful authentication. Without this, one forged frame
permanently breaks a session — the first version of this code had exactly that bug, and
the test that caught it is still there.

**A changed key aborts rather than warns.** A "peer's key changed, continue? [y/N]"
prompt gets clicked through. The session is refused and re-pinning requires an explicit
command. This is deliberately more annoying than the alternative.

**Beacons are signed but not authenticated.** A beacon proves possession of a key. It
does not prove liveness — it can be recorded and replayed. Beacons are discovery hints;
all real authentication happens in the handshake.

**Cover traffic is `DATA`, not its own packet type.** Chaff with a `COVER` type byte in
the header is not chaff, because an observer filters it out in one line. Cover frames are
ordinary `DATA` frames with a random destination tag that nobody recognises.

**Frames addressed to us are still relayed.** Suppressing the relay of frames we could
read would leak which frames were ours to anyone watching relay behaviour.

**Nonces are not advanced on decryption failure.** Otherwise a forged packet
desynchronises a healthy Noise transport session.

---

## Reporting a vulnerability

Open an issue at https://github.com/sk000001/chatbit/issues. Given the status of this
project — unaudited, experimental, no users depending on it — public disclosure is
appropriate and welcome. If that changes, this section will.

Findings that would be most valuable:

- Anything that lets one identity be presented as another
- Anything that lets a relay recover plaintext or link frames to a sender
- Anything that lets forged input desynchronise or exhaust protocol state
- Deviations from the Noise or Double Ratchet specifications
