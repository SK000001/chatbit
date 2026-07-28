#!/usr/bin/env python3
"""Generate the cross-implementation test vectors.

Run this to regenerate everything under ``vectors/``::

    python tools/generate_vectors.py

Every value here is derived from fixed seeds, so the output is byte-identical
on every run and on every machine. If a regenerated file differs from what is
committed, either the protocol changed or something broke -- and
``tests/test_vectors.py`` will fail until the difference is explained.

The vectors exist so that a Swift, Kotlin, Rust or Go implementation can be
checked against this reference without anybody having to read the Python. That
matters more than usual here: reimplementing a handshake and a ratchet by eye,
in a new language, with no way to check intermediate state, is exactly how the
bug class this protocol was built to avoid gets reintroduced.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from chatbit.crypto import identity as identity_mod
from chatbit.crypto.identity import (
    Identity,
    PeerIdentity,
    fingerprint_from_keys,
    safety_number,
)
from chatbit.crypto.noise import PROTOCOL_NAME, CipherState, HandshakeState
from chatbit.crypto.primitives import (
    aead_encrypt,
    dh,
    ed25519_public_bytes,
    hash_sha256,
    hkdf,
    hmac_sha256,
    load_ed25519_private,
    load_x25519_private,
    noise_hkdf,
    sign,
    x25519_public_bytes,
)
from chatbit.crypto.ratchet import (
    DoubleRatchet,
    MessageHeader,
    _kdf_ck,
    _kdf_rk,
    _message_keys,
)
from chatbit.session import PROLOGUE, _derive_session_keys, _encode_identity_payload
from chatbit.wire import tags
from chatbit.wire.fragment import fragment
from chatbit.wire.packet import BROADCAST_TAG, HEADER_LEN, Packet, PacketType
from chatbit.wire.padding import PaddingPolicy, padded_size

VECTORS = Path(__file__).resolve().parent.parent / "vectors"

# Fixed seeds. Chosen to be obviously synthetic so nobody mistakes a vector key
# for something that ever protected anything.
SEEDS = {
    "alice_static": bytes(range(32)),
    "alice_signing": bytes(range(32, 64)),
    "alice_ephemeral": bytes(range(64, 96)),
    "bob_static": bytes(range(96, 128)),
    "bob_signing": bytes(range(128, 160)),
    "bob_ephemeral": bytes(range(160, 192)),
    "bob_ratchet": bytes(range(192, 224)),
    # Ratchet keys are consumed in sequence as the DH ratchet turns. Numbered
    # in the order the chain below actually uses them.
    "alice_ratchet_1": bytes([0xA0 ^ i for i in range(32)]),
    "bob_ratchet_2": bytes([0xB0 ^ i for i in range(32)]),
    "alice_ratchet_3": bytes([0xC0 ^ i for i in range(32)]),
    "bob_ratchet_4": bytes([0xD0 ^ i for i in range(32)]),
}


def h(data: bytes) -> str:
    return data.hex()


def keyed(seed: bytes):
    """A deterministic X25519 keypair factory that always returns ``seed``.

    Only correct where exactly one key is drawn -- a Noise handshake, which
    generates a single ephemeral. For the ratchet use :func:`key_sequence`; a
    constant factory there would hand back the same key after every DH step,
    so the peer would never see a new public key and would never ratchet.
    """
    return lambda: load_x25519_private(seed)


def key_sequence(*seeds: bytes):
    """A factory that yields each seed in turn, then refuses.

    Running out is a hard error rather than a silent wrap-around: it means the
    chain drew more keys than the vector accounts for, and the resulting
    vectors would not describe the protocol.
    """
    remaining = list(seeds)

    def generate():
        if not remaining:
            raise AssertionError(
                "ratchet drew more keys than the vector provides; add another seed"
            )
        return load_x25519_private(remaining.pop(0))

    generate.remaining = remaining  # type: ignore[attr-defined]
    return generate


def write(name: str, payload: dict) -> None:
    VECTORS.mkdir(exist_ok=True)
    path = VECTORS / name
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
    print(f"  wrote {path.relative_to(VECTORS.parent)}")


# ---------------------------------------------------------------------------
# 1. primitives
# ---------------------------------------------------------------------------


def gen_primitives() -> dict:
    """Known-answer tests for the building blocks.

    Getting any of these wrong makes every later vector fail in a way that is
    hard to diagnose, so they are checked first and separately.
    """
    ck = bytes(range(32))
    ikm = b"input key material"

    two = noise_hkdf(ck, ikm, 2)
    three = noise_hkdf(ck, ikm, 3)

    alice_x = load_x25519_private(SEEDS["alice_static"])
    bob_x = load_x25519_private(SEEDS["bob_static"])
    alice_ed = load_ed25519_private(SEEDS["alice_signing"])

    # Nonce counters chosen to catch endianness errors. n=0 and n=1 pass under
    # either byte order; n=2**32 does not, and neither does n=2**39.
    aead_cases = []
    for n in (0, 1, 2**32, 2**39):
        nonce = b"\x00\x00\x00\x00" + n.to_bytes(8, "little")
        aead_cases.append(
            {
                "n": n,
                "nonce": h(nonce),
                "key": h(bytes(range(32))),
                "ad": h(b"associated data"),
                "plaintext": h(b"chatbit vector"),
                "ciphertext": h(
                    aead_encrypt(bytes(range(32)), nonce, b"chatbit vector", b"associated data")
                ),
            }
        )

    return {
        "description": "Known-answer tests for the primitive layer.",
        "sha256": [
            {"input": h(b""), "output": h(hash_sha256(b""))},
            {"input": h(b"chatbit"), "output": h(hash_sha256(b"chatbit"))},
        ],
        "hmac_sha256": [
            {
                "key": h(bytes(range(32))),
                "data": h(b"\x01"),
                "output": h(hmac_sha256(bytes(range(32)), b"\x01")),
            }
        ],
        "hkdf_sha256": [
            {
                "ikm": h(ikm),
                "salt": h(ck),
                "info": h(b"chatbit/v1 session"),
                "length": 96,
                "output": h(hkdf(ikm, ck, b"chatbit/v1 session", 96)),
            }
        ],
        "noise_hkdf": {
            "note": (
                "Noise defines its own expand step (spec section 4.3); it is NOT "
                "HKDF-Expand with an info parameter. temp_key = HMAC(ck, ikm), "
                "out1 = HMAC(temp_key, 0x01), out2 = HMAC(temp_key, out1||0x02), "
                "out3 = HMAC(temp_key, out2||0x03)."
            ),
            "chaining_key": h(ck),
            "input_key_material": h(ikm),
            "two_outputs": [h(two[0]), h(two[1])],
            "three_outputs": [h(three[0]), h(three[1]), h(three[2])],
        },
        "x25519": {
            "note": "An all-zero shared secret MUST be rejected (low-order point).",
            "alice_private": h(SEEDS["alice_static"]),
            "alice_public": h(x25519_public_bytes(alice_x)),
            "bob_private": h(SEEDS["bob_static"]),
            "bob_public": h(x25519_public_bytes(bob_x)),
            "shared_secret": h(dh(alice_x, x25519_public_bytes(bob_x))),
        },
        "ed25519": {
            "private": h(SEEDS["alice_signing"]),
            "public": h(ed25519_public_bytes(alice_ed)),
            "message": h(b"chatbit/v1 identity-binding" + b"\x00" * 32),
            "signature": h(
                sign(alice_ed, b"chatbit/v1 identity-binding" + b"\x00" * 32)
            ),
        },
        "chacha20poly1305_noise_nonce": {
            "note": (
                "Noise builds a 12-byte nonce as 4 zero bytes followed by the "
                "64-bit counter in LITTLE-endian order."
            ),
            "cases": aead_cases,
        },
    }


# ---------------------------------------------------------------------------
# 2. Noise XX handshake
# ---------------------------------------------------------------------------


def gen_noise_xx() -> dict:
    """A complete handshake with every intermediate value exposed.

    ``h`` and ``ck`` are recorded after each step so a port that diverges can
    find the exact operation where it went wrong, rather than only learning
    that the final keys disagree.
    """
    alice = Identity(
        load_ed25519_private(SEEDS["alice_signing"]),
        load_x25519_private(SEEDS["alice_static"]),
        "alice",
    )
    bob = Identity(
        load_ed25519_private(SEEDS["bob_signing"]),
        load_x25519_private(SEEDS["bob_static"]),
        "bob",
    )
    bob_ratchet = load_x25519_private(SEEDS["bob_ratchet"])

    hs_i = HandshakeState(
        initiator=True,
        static_private=alice.static_private,
        prologue=PROLOGUE,
        ephemeral_factory=keyed(SEEDS["alice_ephemeral"]),
    )
    hs_r = HandshakeState(
        initiator=False,
        static_private=bob.static_private,
        prologue=PROLOGUE,
        ephemeral_factory=keyed(SEEDS["bob_ephemeral"]),
    )

    steps = [
        {
            "step": "initialize",
            "protocol_name": PROTOCOL_NAME.decode(),
            "prologue": h(PROLOGUE),
            "h_after_prologue": h(hs_i.symmetric.h),
            "ck_after_prologue": h(hs_i.symmetric.ck),
        }
    ]

    msg1 = hs_i.write_message_1()
    hs_r.read_message_1(msg1)
    steps.append(
        {
            "step": "message_1",
            "pattern": "-> e",
            "message": h(msg1),
            "h": h(hs_i.symmetric.h),
            "ck": h(hs_i.symmetric.ck),
        }
    )
    assert hs_i.symmetric.h == hs_r.symmetric.h

    signed_h_2 = {}

    def payload_2(handshake_hash: bytes) -> bytes:
        signed_h_2["h"] = handshake_hash
        return _encode_identity_payload(
            bob, handshake_hash, x25519_public_bytes(bob_ratchet)
        )

    msg2 = hs_r.write_message_2(payload_2)
    rs2, signed_hash_2, payload_bytes_2 = hs_i.read_message_2(msg2)
    steps.append(
        {
            "step": "message_2",
            "pattern": "<- e, ee, s, es",
            "message": h(msg2),
            "signed_handshake_hash": h(signed_h_2["h"]),
            "decrypted_payload": h(payload_bytes_2),
            "payload_layout": "ed25519_pub(32) || sig(64) || ratchet_pub(32) || nick_len(1) || nick",
            "remote_static_learned": h(rs2),
            "h": h(hs_i.symmetric.h),
            "ck": h(hs_i.symmetric.ck),
        }
    )
    assert hs_i.symmetric.h == hs_r.symmetric.h
    assert signed_hash_2 == signed_h_2["h"]

    signed_h_3 = {}

    def payload_3(handshake_hash: bytes) -> bytes:
        signed_h_3["h"] = handshake_hash
        return _encode_identity_payload(alice, handshake_hash, None)

    msg3 = hs_i.write_message_3(payload_3)
    rs3, signed_hash_3, payload_bytes_3 = hs_r.read_message_3(msg3)
    steps.append(
        {
            "step": "message_3",
            "pattern": "-> s, se",
            "message": h(msg3),
            "signed_handshake_hash": h(signed_h_3["h"]),
            "decrypted_payload": h(payload_bytes_3),
            "payload_layout": "ed25519_pub(32) || sig(64) || nick_len(1) || nick",
            "remote_static_learned": h(rs3),
            "h": h(hs_i.symmetric.h),
            "ck": h(hs_i.symmetric.ck),
        }
    )

    assert hs_i.symmetric.h == hs_r.symmetric.h
    assert hs_i.chaining_key() == hs_r.chaining_key()

    send_i, recv_i = hs_i.split()
    send_r, recv_r = hs_r.split()
    assert send_i.k == recv_r.k and recv_i.k == send_r.k

    root_key, i2r, r2i = _derive_session_keys(
        hs_i.chaining_key(), hs_i.handshake_hash
    )

    return {
        "description": (
            "A full Noise_XX_25519_ChaChaPoly_SHA256 handshake with chatbit's "
            "identity-binding payloads. All intermediate h and ck values are "
            "included so a port can localise a divergence."
        ),
        "inputs": {
            "prologue": h(PROLOGUE),
            "initiator": {
                "nickname": alice.nickname,
                "static_private": h(SEEDS["alice_static"]),
                "static_public": h(alice.static_public),
                "signing_private": h(SEEDS["alice_signing"]),
                "signing_public": h(alice.signing_public),
                "ephemeral_private": h(SEEDS["alice_ephemeral"]),
            },
            "responder": {
                "nickname": bob.nickname,
                "static_private": h(SEEDS["bob_static"]),
                "static_public": h(bob.static_public),
                "signing_private": h(SEEDS["bob_signing"]),
                "signing_public": h(bob.signing_public),
                "ephemeral_private": h(SEEDS["bob_ephemeral"]),
                "ratchet_private": h(SEEDS["bob_ratchet"]),
                "ratchet_public": h(x25519_public_bytes(bob_ratchet)),
            },
        },
        "identity_signature": {
            "domain": "chatbit/v1 identity-binding",
            "note": (
                "Signed message is DOMAIN || h, where h is the transcript hash "
                "BEFORE the payload is encrypted. This binds the identity to "
                "this specific handshake and is what makes replay across "
                "sessions fail."
            ),
        },
        "transcript": steps,
        "outputs": {
            "handshake_hash": h(hs_i.handshake_hash),
            "chaining_key": h(hs_i.chaining_key()),
            "split_initiator_send_key": h(send_i.k),
            "split_initiator_recv_key": h(recv_i.k),
            "session_root_key": h(root_key),
            "session_i2r_tag_key": h(i2r),
            "session_r2i_tag_key": h(r2i),
            "session_kdf": (
                "HKDF(ikm=chaining_key, salt=handshake_hash, "
                "info='chatbit/v1 session', len=96) -> root||i2r_tag||r2i_tag"
            ),
        },
    }


# ---------------------------------------------------------------------------
# 3. Double Ratchet
# ---------------------------------------------------------------------------


def gen_ratchet() -> dict:
    """A ratchet chain covering the cases ports get wrong.

    Sequential sends, a direction change (DH ratchet step), out-of-order
    arrival, and skipped keys. Each is a separate opportunity to diverge.
    """
    shared = bytes([0x5A] * 32)
    bob_ratchet = load_x25519_private(SEEDS["bob_ratchet"])

    # Key draw order over the chain below:
    #   alice: _1 at init_sender, _3 when she ratchets on the responder's reply
    #   bob:   _2 when he ratchets on her first message, _4 on her post-step message
    alice_keys = key_sequence(SEEDS["alice_ratchet_1"], SEEDS["alice_ratchet_3"])
    bob_keys = key_sequence(SEEDS["bob_ratchet_2"], SEEDS["bob_ratchet_4"])

    alice = DoubleRatchet.init_sender(
        shared, x25519_public_bytes(bob_ratchet), keygen=alice_keys
    )
    bob = DoubleRatchet.init_receiver(shared, bob_ratchet, keygen=bob_keys)

    messages: list[dict] = []
    schedule: list[dict] = []
    held: dict[int, tuple] = {}
    parties = {"initiator": alice, "responder": bob}
    peers = {"initiator": bob, "responder": alice}

    def send(label, plaintext, ad=b"", note=""):
        """Encrypt one message and record it, without delivering it yet."""
        header, ct = parties[label].encrypt(plaintext, ad)
        index = len(messages)
        messages.append(
            {
                "index": index,
                "from": label,
                "plaintext": h(plaintext),
                "associated_data": h(ad),
                "header": {
                    "ratchet_public": h(header.ratchet_pub),
                    "pn": header.pn,
                    "n": header.n,
                    "encoded": h(header.encode()),
                },
                "ciphertext": h(ct),
            }
        )
        held[index] = (label, header, ct, ad)
        schedule.append({"op": "send", "index": index, "note": note})
        return index

    def deliver(index, note=""):
        """Decrypt a previously sent message at this point in the schedule."""
        label, header, ct, ad = held[index]
        plaintext = peers[label].decrypt(header, ct, ad)
        assert plaintext == bytes.fromhex(messages[index]["plaintext"])
        schedule.append({"op": "deliver", "index": index, "note": note})

    # Three from the initiator on her first sending chain.
    send("initiator", b"first message", note="first chain")
    send("initiator", b"second message")
    send("initiator", b"third message", ad=b"chatbit-ad", note="non-empty associated data")
    deliver(0, note="responder DH-ratchets here, deriving his receiving chain")
    deliver(1)
    deliver(2)

    # Direction change. The responder can only send once he has received.
    send("responder", b"reply from responder", note="responder's first send")
    deliver(3, note="initiator DH-ratchets here")

    send("initiator", b"after the ratchet step", note="initiator's second chain")
    deliver(4, note="responder DH-ratchets again")

    # Out-of-order: three sent, the last delivered first.
    send("initiator", b"ooo-a")
    send("initiator", b"ooo-b")
    send("initiator", b"ooo-c")
    deliver(7, note="arrives early; keys for 5 and 6 are stored as skipped")
    deliver(5, note="skipped key recovered")
    deliver(6, note="skipped key recovered")

    # Every provisioned ratchet key must have been used, and no more drawn.
    # If this trips, the chain changed and the vectors need re-deriving.
    assert not alice_keys.remaining, "unused initiator ratchet keys"
    assert not bob_keys.remaining, "unused responder ratchet keys"

    # Chain KDF exposed directly, so a port can check the symmetric ratchet
    # in isolation from the AEAD.
    ck = bytes([0x11] * 32)
    next_ck, mk = _kdf_ck(ck)
    msg_key, msg_nonce = _message_keys(mk)
    rk_in = bytes([0x22] * 32)
    dh_out = bytes([0x33] * 32)
    new_rk, new_ck = _kdf_rk(rk_in, dh_out)

    return {
        "description": (
            "Double Ratchet chain: sequential sends, a DH ratchet step on "
            "direction change, and out-of-order delivery with skipped keys."
        ),
        "inputs": {
            "shared_key": h(shared),
            "responder_ratchet_private": h(SEEDS["bob_ratchet"]),
            "responder_ratchet_public": h(x25519_public_bytes(bob_ratchet)),
            "note": (
                "Ratchet keys are drawn in this order as the DH ratchet turns. "
                "An implementation replaying this chain must substitute them in "
                "sequence wherever it would otherwise generate a fresh keypair."
            ),
            "initiator_ratchet_privates": [
                h(SEEDS["alice_ratchet_1"]),
                h(SEEDS["alice_ratchet_3"]),
            ],
            "responder_ratchet_privates": [
                h(SEEDS["bob_ratchet_2"]),
                h(SEEDS["bob_ratchet_4"]),
            ],
        },
        "schedule": schedule,
        "schedule_note": (
            "Replay these operations in order. 'send' encrypts messages[index] "
            "from that party; 'deliver' decrypts a previously sent message. The "
            "interleaving is load-bearing -- a party has no sending chain until "
            "it has received at least one message, and the out-of-order "
            "deliveries at the end exercise the skipped-key path."
        ),
        "kdf": {
            "kdf_rk": {
                "note": "HKDF(ikm=dh_output, salt=root_key, info='chatbit/v1 ratchet-root', len=64) -> new_root||chain_key",
                "root_key": h(rk_in),
                "dh_output": h(dh_out),
                "new_root_key": h(new_rk),
                "new_chain_key": h(new_ck),
            },
            "kdf_ck": {
                "note": "message_key = HMAC(ck, 0x01); next_ck = HMAC(ck, 0x02)",
                "chain_key": h(ck),
                "message_key": h(mk),
                "next_chain_key": h(next_ck),
            },
            "message_keys": {
                "note": "HKDF(ikm=message_key, salt=32 zero bytes, info='chatbit/v1 message-key', len=44) -> aead_key(32)||nonce(12)",
                "message_key": h(mk),
                "aead_key": h(msg_key),
                "aead_nonce": h(msg_nonce),
            },
        },
        "header_format": {
            "layout": "ratchet_public(32) || pn(4, big-endian) || n(4, big-endian)",
            "length": 40,
        },
        "aead_associated_data": (
            "associated_data || header.encode() -- the header is authenticated "
            "even though it travels in the clear"
        ),
        "messages": messages,
    }


# ---------------------------------------------------------------------------
# 4. wire format
# ---------------------------------------------------------------------------


def gen_wire() -> dict:
    msg_id = bytes.fromhex("0011223344556677")
    dst_tag = bytes.fromhex("8899aabbccddeeff")

    simple = Packet(
        ptype=PacketType.DATA,
        payload=b"encrypted payload bytes",
        msg_id=msg_id,
        dst_tag=dst_tag,
        ttl=7,
    )

    broadcast = Packet(
        ptype=PacketType.BEACON,
        payload=b"beacon body",
        msg_id=msg_id,
        dst_tag=BROADCAST_TAG,
        ttl=3,
    )

    long_payload = bytes((i * 7) % 256 for i in range(500))
    frags = fragment(
        PacketType.DATA, long_payload, msg_id, 177, dst_tag, ttl=7
    )

    return {
        "description": "Frame encoding, padding and fragmentation.",
        "header": {
            "length": HEADER_LEN,
            "layout": [
                {"offset": 0, "size": 1, "field": "version"},
                {"offset": 1, "size": 1, "field": "ptype"},
                {"offset": 2, "size": 1, "field": "ttl"},
                {"offset": 3, "size": 1, "field": "frag_index"},
                {"offset": 4, "size": 1, "field": "frag_count"},
                {"offset": 5, "size": 8, "field": "msg_id"},
                {"offset": 13, "size": 8, "field": "dst_tag"},
                {"offset": 21, "size": 2, "field": "payload_len (big-endian)"},
                {"offset": 23, "size": "payload_len", "field": "payload"},
            ],
            "note": "All multi-byte integers in the frame header are big-endian.",
        },
        "packet_types": {p.name: p.value for p in PacketType},
        "broadcast_tag": h(BROADCAST_TAG),
        "packets": [
            {
                "name": "data_frame",
                "ptype": "DATA",
                "ttl": 7,
                "msg_id": h(msg_id),
                "dst_tag": h(dst_tag),
                "payload": h(simple.payload),
                "encoded": h(simple.encode()),
                "encoded_padded_200": h(simple.encode(pad_to=200)),
            },
            {
                "name": "broadcast_beacon",
                "ptype": "BEACON",
                "ttl": 3,
                "msg_id": h(msg_id),
                "dst_tag": h(BROADCAST_TAG),
                "payload": h(broadcast.payload),
                "encoded": h(broadcast.encode()),
            },
        ],
        "padding": {
            "policies": {
                "strict": "pad every frame to the MTU",
                "bucket": "pad to the next value in the ladder",
                "none": "no padding",
            },
            "bucket_ladder": [32, 64, 96, 128, 192, 256, 384, 512, 768, 1024],
            "cases": [
                {
                    "frame_len": n,
                    "mtu": 200,
                    "strict": padded_size(n, 200, PaddingPolicy.STRICT),
                    "bucket": padded_size(n, 200, PaddingPolicy.BUCKET),
                    "none": padded_size(n, 200, PaddingPolicy.NONE),
                }
                for n in (23, 30, 33, 64, 100, 190, 198, 200)
            ],
        },
        "fragmentation": {
            "capacity": 177,
            "payload_len": len(long_payload),
            "payload": h(long_payload),
            "fragment_count": len(frags),
            "fragments": [
                {
                    "frag_index": f.frag_index,
                    "frag_count": f.frag_count,
                    "payload_len": len(f.payload),
                    "encoded": h(f.encode()),
                }
                for f in frags
            ],
        },
    }


# ---------------------------------------------------------------------------
# 5. tags and identity
# ---------------------------------------------------------------------------


def gen_tags_identity() -> dict:
    tag_key = bytes([0x77] * 32)
    static_pub = x25519_public_bytes(load_x25519_private(SEEDS["bob_static"]))

    alice = Identity(
        load_ed25519_private(SEEDS["alice_signing"]),
        load_x25519_private(SEEDS["alice_static"]),
        "alice",
    )
    bob = Identity(
        load_ed25519_private(SEEDS["bob_signing"]),
        load_x25519_private(SEEDS["bob_static"]),
        "bob",
    )

    return {
        "description": "Rotating recipient tags, fingerprints and safety numbers.",
        "tags": {
            "epoch_seconds": tags.EPOCH_SECONDS,
            "epoch_skew_accepted": tags.EPOCH_SKEW,
            "session_tag": {
                "formula": "HMAC-SHA256(tag_key, 'chatbit/v1 tag' || epoch_be64)[:8]",
                "tag_key": h(tag_key),
                "cases": [
                    {"epoch": e, "tag": h(tags.compute_tag(tag_key, epoch=e))}
                    for e in (0, 1, 1000, 2_000_000)
                ],
            },
            "handshake_tag": {
                "formula": "HMAC-SHA256(responder_static_pub, 'chatbit/v1 handshake-tag' || epoch_be64)[:8]",
                "responder_static_public": h(static_pub),
                "cases": [
                    {"epoch": e, "tag": h(tags.handshake_tag(static_pub, epoch=e))}
                    for e in (0, 1, 1000, 2_000_000)
                ],
            },
        },
        "identity": {
            "fingerprint_formula": "SHA256('chatbit/v1 fingerprint' || ed25519_pub || x25519_pub)",
            "alice": {
                "signing_public": h(alice.signing_public),
                "static_public": h(alice.static_public),
                "fingerprint": h(alice.fingerprint),
                "short_id": alice.short_id,
            },
            "bob": {
                "signing_public": h(bob.signing_public),
                "static_public": h(bob.static_public),
                "fingerprint": h(bob.fingerprint),
                "short_id": bob.short_id,
            },
            "safety_number": {
                "formula": (
                    "sort the two fingerprints, then "
                    "HKDF(ikm=lo||hi, salt='', info='chatbit/v1 safety-number', len=30); "
                    "each byte -> last two digits of its 3-digit decimal form; "
                    "take 60 digits, group in fives"
                ),
                "note": "Order-independent: both parties compute the same string.",
                "value": safety_number(alice.fingerprint, bob.fingerprint),
                "value_reversed_args": safety_number(
                    bob.fingerprint, alice.fingerprint
                ),
            },
        },
    }


def main() -> int:
    print("generating chatbit protocol vectors")
    write("primitives.json", gen_primitives())
    write("noise_xx.json", gen_noise_xx())
    write("ratchet.json", gen_ratchet())
    write("wire.json", gen_wire())
    write("tags_identity.json", gen_tags_identity())
    print("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
