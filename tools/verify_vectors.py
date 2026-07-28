#!/usr/bin/env python3
"""Verify an implementation against the committed test vectors.

    python tools/verify_vectors.py

For the reference implementation this is a regression test: it catches
accidental protocol drift, because changing any derivation changes the vectors
and this fails until they are regenerated deliberately.

For a port, this file is the specification of *what to check*. Reimplement it
in your language, keep the same check names, and you have a conformance suite.
Passing every check here means your implementation can talk to this one.

Checks are ordered so that a failure points at the lowest broken layer:
primitives first, then Noise, then the ratchet, then the wire format. A wrong
HKDF makes everything above it fail, and there is no point reading a handshake
mismatch when the real problem is two layers down.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from chatbit.crypto.identity import Identity, fingerprint_from_keys, safety_number
from chatbit.crypto.noise import HandshakeState
from chatbit.crypto.primitives import (
    aead_decrypt,
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
    verify,
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
from chatbit.wire.fragment import Reassembler, fragment
from chatbit.wire.packet import Packet, PacketType
from chatbit.wire.padding import PaddingPolicy, padded_size

VECTORS = Path(__file__).resolve().parent.parent / "vectors"


class Failure(Exception):
    pass


class Checker:
    def __init__(self, verbose: bool = True) -> None:
        self.passed = 0
        self.failures: list[str] = []
        self.verbose = verbose

    def check(self, name: str, actual, expected) -> None:
        if isinstance(actual, bytes):
            actual = actual.hex()
        if isinstance(expected, bytes):
            expected = expected.hex()
        if actual == expected:
            self.passed += 1
        else:
            self.failures.append(f"{name}\n    expected: {expected}\n    actual:   {actual}")

    def ok(self, name: str, condition: bool) -> None:
        if condition:
            self.passed += 1
        else:
            self.failures.append(f"{name}\n    condition was false")

    def section(self, title: str) -> None:
        if self.verbose:
            print(f"  {title}")


def load(name: str) -> dict:
    with open(VECTORS / name) as fh:
        return json.load(fh)


def unhex(s: str) -> bytes:
    return bytes.fromhex(s)


# ---------------------------------------------------------------------------


def verify_primitives(c: Checker) -> None:
    v = load("primitives.json")
    c.section("primitives")

    for case in v["sha256"]:
        c.check("sha256", hash_sha256(unhex(case["input"])), case["output"])

    for case in v["hmac_sha256"]:
        c.check(
            "hmac_sha256",
            hmac_sha256(unhex(case["key"]), unhex(case["data"])),
            case["output"],
        )

    for case in v["hkdf_sha256"]:
        c.check(
            "hkdf_sha256",
            hkdf(unhex(case["ikm"]), unhex(case["salt"]), unhex(case["info"]), case["length"]),
            case["output"],
        )

    nh = v["noise_hkdf"]
    two = noise_hkdf(unhex(nh["chaining_key"]), unhex(nh["input_key_material"]), 2)
    three = noise_hkdf(unhex(nh["chaining_key"]), unhex(nh["input_key_material"]), 3)
    c.check("noise_hkdf/2", [x.hex() for x in two], nh["two_outputs"])
    c.check("noise_hkdf/3", [x.hex() for x in three], nh["three_outputs"])

    x = v["x25519"]
    priv = load_x25519_private(unhex(x["alice_private"]))
    c.check("x25519/public", x25519_public_bytes(priv), x["alice_public"])
    c.check("x25519/shared", dh(priv, unhex(x["bob_public"])), x["shared_secret"])

    e = v["ed25519"]
    ed = load_ed25519_private(unhex(e["private"]))
    c.check("ed25519/public", ed25519_public_bytes(ed), e["public"])
    c.check("ed25519/sign", sign(ed, unhex(e["message"])), e["signature"])
    c.ok(
        "ed25519/verify",
        verify(unhex(e["public"]), unhex(e["signature"]), unhex(e["message"])),
    )

    for case in v["chacha20poly1305_noise_nonce"]["cases"]:
        # The nonce encoding is the thing under test: n as 64-bit LITTLE-endian
        # after four zero bytes. n=2**32 and n=2**39 catch byte-order errors
        # that n=0 and n=1 pass straight through.
        nonce = b"\x00\x00\x00\x00" + case["n"].to_bytes(8, "little")
        c.check(f"noise_nonce/n={case['n']}", nonce, case["nonce"])
        ct = aead_encrypt(
            unhex(case["key"]), nonce, unhex(case["plaintext"]), unhex(case["ad"])
        )
        c.check(f"chachapoly/n={case['n']}", ct, case["ciphertext"])
        c.check(
            f"chachapoly/roundtrip/n={case['n']}",
            aead_decrypt(unhex(case["key"]), nonce, ct, unhex(case["ad"])),
            case["plaintext"],
        )


def verify_noise(c: Checker) -> None:
    v = load("noise_xx.json")
    c.section("noise xx handshake")
    inp = v["inputs"]

    alice = Identity(
        load_ed25519_private(unhex(inp["initiator"]["signing_private"])),
        load_x25519_private(unhex(inp["initiator"]["static_private"])),
        inp["initiator"]["nickname"],
    )
    bob = Identity(
        load_ed25519_private(unhex(inp["responder"]["signing_private"])),
        load_x25519_private(unhex(inp["responder"]["static_private"])),
        inp["responder"]["nickname"],
    )
    bob_ratchet = load_x25519_private(unhex(inp["responder"]["ratchet_private"]))

    c.check("noise/alice_static_pub", alice.static_public, inp["initiator"]["static_public"])
    c.check("noise/bob_static_pub", bob.static_public, inp["responder"]["static_public"])
    c.check(
        "noise/bob_ratchet_pub",
        x25519_public_bytes(bob_ratchet),
        inp["responder"]["ratchet_public"],
    )

    hs_i = HandshakeState(
        initiator=True,
        static_private=alice.static_private,
        prologue=unhex(inp["prologue"]),
        ephemeral_factory=lambda: load_x25519_private(
            unhex(inp["initiator"]["ephemeral_private"])
        ),
    )
    hs_r = HandshakeState(
        initiator=False,
        static_private=bob.static_private,
        prologue=unhex(inp["prologue"]),
        ephemeral_factory=lambda: load_x25519_private(
            unhex(inp["responder"]["ephemeral_private"])
        ),
    )

    steps = {s["step"]: s for s in v["transcript"]}

    init = steps["initialize"]
    c.check("noise/h_after_prologue", hs_i.symmetric.h, init["h_after_prologue"])
    c.check("noise/ck_after_prologue", hs_i.symmetric.ck, init["ck_after_prologue"])

    msg1 = hs_i.write_message_1()
    hs_r.read_message_1(msg1)
    s1 = steps["message_1"]
    c.check("noise/msg1", msg1, s1["message"])
    c.check("noise/msg1_h", hs_i.symmetric.h, s1["h"])
    c.check("noise/msg1_ck", hs_i.symmetric.ck, s1["ck"])

    s2 = steps["message_2"]
    captured = {}

    def payload_2(handshake_hash: bytes) -> bytes:
        captured["h"] = handshake_hash
        return _encode_identity_payload(
            bob, handshake_hash, x25519_public_bytes(bob_ratchet)
        )

    msg2 = hs_r.write_message_2(payload_2)
    c.check("noise/msg2", msg2, s2["message"])
    c.check("noise/msg2_signed_h", captured["h"], s2["signed_handshake_hash"])

    rs2, signed_h2, payload2 = hs_i.read_message_2(msg2)
    c.check("noise/msg2_remote_static", rs2, s2["remote_static_learned"])
    c.check("noise/msg2_payload", payload2, s2["decrypted_payload"])
    c.check("noise/msg2_h", hs_i.symmetric.h, s2["h"])
    c.check("noise/msg2_ck", hs_i.symmetric.ck, s2["ck"])

    # The identity proof must verify against the transcript hash the writer signed.
    c.ok(
        "noise/msg2_identity_signature",
        verify(
            payload2[:32],
            payload2[32:96],
            b"chatbit/v1 identity-binding" + signed_h2,
        ),
    )

    s3 = steps["message_3"]
    captured3 = {}

    def payload_3(handshake_hash: bytes) -> bytes:
        captured3["h"] = handshake_hash
        return _encode_identity_payload(alice, handshake_hash, None)

    msg3 = hs_i.write_message_3(payload_3)
    c.check("noise/msg3", msg3, s3["message"])
    rs3, signed_h3, payload3 = hs_r.read_message_3(msg3)
    c.check("noise/msg3_remote_static", rs3, s3["remote_static_learned"])
    c.check("noise/msg3_payload", payload3, s3["decrypted_payload"])
    c.check("noise/msg3_h", hs_r.symmetric.h, s3["h"])
    c.ok(
        "noise/msg3_identity_signature",
        verify(
            payload3[:32],
            payload3[32:96],
            b"chatbit/v1 identity-binding" + signed_h3,
        ),
    )

    out = v["outputs"]
    c.check("noise/handshake_hash", hs_i.handshake_hash, out["handshake_hash"])
    c.check("noise/chaining_key", hs_i.chaining_key(), out["chaining_key"])
    c.ok("noise/hash_agreement", hs_i.handshake_hash == hs_r.handshake_hash)

    send_i, recv_i = hs_i.split()
    send_r, recv_r = hs_r.split()
    c.check("noise/split_send", send_i.k, out["split_initiator_send_key"])
    c.check("noise/split_recv", recv_i.k, out["split_initiator_recv_key"])
    c.ok("noise/split_mirrors", send_i.k == recv_r.k and recv_i.k == send_r.k)

    root, i2r, r2i = _derive_session_keys(hs_i.chaining_key(), hs_i.handshake_hash)
    c.check("session/root_key", root, out["session_root_key"])
    c.check("session/i2r_tag_key", i2r, out["session_i2r_tag_key"])
    c.check("session/r2i_tag_key", r2i, out["session_r2i_tag_key"])


def verify_ratchet(c: Checker) -> None:
    v = load("ratchet.json")
    c.section("double ratchet")
    inp = v["inputs"]

    kdf = v["kdf"]
    rk_case = kdf["kdf_rk"]
    new_rk, new_ck = _kdf_rk(unhex(rk_case["root_key"]), unhex(rk_case["dh_output"]))
    c.check("ratchet/kdf_rk_root", new_rk, rk_case["new_root_key"])
    c.check("ratchet/kdf_rk_chain", new_ck, rk_case["new_chain_key"])

    ck_case = kdf["kdf_ck"]
    next_ck, mk = _kdf_ck(unhex(ck_case["chain_key"]))
    c.check("ratchet/kdf_ck_msg", mk, ck_case["message_key"])
    c.check("ratchet/kdf_ck_next", next_ck, ck_case["next_chain_key"])

    mk_case = kdf["message_keys"]
    key, nonce = _message_keys(unhex(mk_case["message_key"]))
    c.check("ratchet/message_key_aead", key, mk_case["aead_key"])
    c.check("ratchet/message_key_nonce", nonce, mk_case["aead_nonce"])

    # Replay the recorded schedule. The interleaving of sends and deliveries
    # is part of the vector: a party has no sending chain until it has
    # received, so encrypting everything up front would not even run.
    alice, bob = _build_pair(inp)
    parties = {"initiator": alice, "responder": bob}
    peers = {"initiator": bob, "responder": alice}
    messages = {m["index"]: m for m in v["messages"]}
    held: dict[int, tuple] = {}

    for step in v["schedule"]:
        index = step["index"]
        m = messages[index]
        ad = unhex(m["associated_data"])

        if step["op"] == "send":
            header, ct = parties[m["from"]].encrypt(unhex(m["plaintext"]), ad)
            held[index] = (m["from"], header, ct, ad)
            c.check(f"ratchet/msg{index}/header", header.encode(), m["header"]["encoded"])
            c.check(
                f"ratchet/msg{index}/ratchet_pub",
                header.ratchet_pub,
                m["header"]["ratchet_public"],
            )
            c.check(f"ratchet/msg{index}/n", header.n, m["header"]["n"])
            c.check(f"ratchet/msg{index}/pn", header.pn, m["header"]["pn"])
            c.check(f"ratchet/msg{index}/ciphertext", ct, m["ciphertext"])
        elif step["op"] == "deliver":
            label, header, ct, ad = held[index]
            plaintext = peers[label].decrypt(header, ct, ad)
            c.check(f"ratchet/decrypt{index}", plaintext, m["plaintext"])
        else:
            raise Failure(f"unknown schedule op {step['op']!r}")


def _key_sequence(seed_hexes: list[str]):
    """Yield each pinned ratchet key in turn, refusing to over-draw."""
    remaining = [unhex(s) for s in seed_hexes]

    def generate():
        if not remaining:
            raise Failure("ratchet drew more keys than the vector provides")
        return load_x25519_private(remaining.pop(0))

    return generate


def _build_pair(inp: dict) -> tuple[DoubleRatchet, DoubleRatchet]:
    shared = unhex(inp["shared_key"])
    bob_ratchet = load_x25519_private(unhex(inp["responder_ratchet_private"]))
    alice = DoubleRatchet.init_sender(
        shared,
        x25519_public_bytes(bob_ratchet),
        keygen=_key_sequence(inp["initiator_ratchet_privates"]),
    )
    bob = DoubleRatchet.init_receiver(
        shared, bob_ratchet, keygen=_key_sequence(inp["responder_ratchet_privates"])
    )
    return alice, bob


def verify_wire(c: Checker) -> None:
    v = load("wire.json")
    c.section("wire format")

    c.check("wire/header_len", 23, v["header"]["length"])
    for name, value in v["packet_types"].items():
        c.check(f"wire/type/{name}", int(PacketType[name]), value)

    for case in v["packets"]:
        packet = Packet(
            ptype=PacketType[case["ptype"]],
            payload=unhex(case["payload"]),
            msg_id=unhex(case["msg_id"]),
            dst_tag=unhex(case["dst_tag"]),
            ttl=case["ttl"],
        )
        c.check(f"wire/{case['name']}/encode", packet.encode(), case["encoded"])
        decoded = Packet.decode(unhex(case["encoded"]))
        c.check(f"wire/{case['name']}/decode_payload", decoded.payload, case["payload"])
        c.check(f"wire/{case['name']}/decode_ttl", decoded.ttl, case["ttl"])
        if "encoded_padded_200" in case:
            c.check(
                f"wire/{case['name']}/pad200",
                packet.encode(pad_to=200),
                case["encoded_padded_200"],
            )
            # Padding must not leak into the recovered payload.
            c.check(
                f"wire/{case['name']}/pad_strip",
                Packet.decode(unhex(case["encoded_padded_200"])).payload,
                case["payload"],
            )

    for case in v["padding"]["cases"]:
        for policy in ("strict", "bucket", "none"):
            c.check(
                f"wire/padding/{policy}/{case['frame_len']}",
                padded_size(case["frame_len"], case["mtu"], PaddingPolicy(policy)),
                case[policy],
            )

    frag = v["fragmentation"]
    packets = fragment(
        PacketType.DATA,
        unhex(frag["payload"]),
        unhex(v["packets"][0]["msg_id"]),
        frag["capacity"],
        unhex(v["packets"][0]["dst_tag"]),
        ttl=7,
    )
    c.check("wire/fragment_count", len(packets), frag["fragment_count"])
    for expected, actual in zip(frag["fragments"], packets):
        c.check(
            f"wire/fragment{expected['frag_index']}", actual.encode(), expected["encoded"]
        )

    reassembler = Reassembler()
    result = None
    for packet in packets:
        result = reassembler.add(packet) or result
    c.check("wire/reassemble", result, frag["payload"])


def verify_tags_identity(c: Checker) -> None:
    v = load("tags_identity.json")
    c.section("tags and identity")

    t = v["tags"]
    c.check("tags/epoch_seconds", tags.EPOCH_SECONDS, t["epoch_seconds"])
    key = unhex(t["session_tag"]["tag_key"])
    for case in t["session_tag"]["cases"]:
        c.check(
            f"tags/session/epoch{case['epoch']}",
            tags.compute_tag(key, epoch=case["epoch"]),
            case["tag"],
        )
    static_pub = unhex(t["handshake_tag"]["responder_static_public"])
    for case in t["handshake_tag"]["cases"]:
        c.check(
            f"tags/handshake/epoch{case['epoch']}",
            tags.handshake_tag(static_pub, epoch=case["epoch"]),
            case["tag"],
        )

    ident = v["identity"]
    for name in ("alice", "bob"):
        entry = ident[name]
        # A fingerprint is a pure function of the two public keys.
        c.check(
            f"identity/{name}/fingerprint",
            fingerprint_from_keys(
                unhex(entry["signing_public"]), unhex(entry["static_public"])
            ),
            entry["fingerprint"],
        )
        c.check(
            f"identity/{name}/short_id",
            unhex(entry["fingerprint"])[:4].hex(),
            entry["short_id"],
        )

    sn = ident["safety_number"]
    computed = safety_number(
        unhex(ident["alice"]["fingerprint"]), unhex(ident["bob"]["fingerprint"])
    )
    c.check("identity/safety_number", computed, sn["value"])
    c.check("identity/safety_number_order_independent", sn["value"], sn["value_reversed_args"])


# ---------------------------------------------------------------------------


def run(verbose: bool = True) -> Checker:
    c = Checker(verbose=verbose)
    verify_primitives(c)
    verify_noise(c)
    verify_ratchet(c)
    verify_wire(c)
    verify_tags_identity(c)
    return c


def main() -> int:
    print("verifying implementation against vectors/")
    c = run()
    print()
    if c.failures:
        for failure in c.failures:
            print(f"  FAIL  {failure}")
        print(f"\n{c.passed} passed, {len(c.failures)} FAILED")
        return 1
    print(f"{c.passed} checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
