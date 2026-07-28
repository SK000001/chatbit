"""Tests for the attacks this protocol is specifically meant to resist.

Several of these target the exact failure modes reported against bitchat in
July 2025: impersonation through a broken identity binding, and trust decisions
made on attacker-controlled display names.
"""

from __future__ import annotations

import pytest

from chatbit.crypto.identity import (
    Identity,
    KeyChangedError,
    PeerIdentity,
    TrustStore,
    safety_number,
)
from chatbit.crypto.noise import HandshakeState, NoiseError
from chatbit.crypto.primitives import generate_x25519, x25519_public_bytes
from chatbit.crypto.ratchet import DoubleRatchet, MessageHeader, RatchetError
from chatbit.session import PROLOGUE, SessionError, SessionManager


def run_handshake(initiator: SessionManager, responder: SessionManager):
    """Drive a full three-message handshake between two managers."""
    init_payload, _tag = initiator.start_handshake(responder.identity.static_public)
    resp_payload = responder.handle_init(init_payload)
    assert resp_payload is not None
    fin_payload, init_session = initiator.handle_response(resp_payload)
    resp_session = responder.handle_fin(fin_payload)
    return init_session, resp_session


def manager(name: str) -> SessionManager:
    return SessionManager(Identity.generate(name), TrustStore(None))


# ---------------------------------------------------------------------------
# identity binding
# ---------------------------------------------------------------------------


def test_handshake_binds_identity_to_transcript():
    """The signature must cover the live transcript, not a constant."""
    alice, bob = manager("alice"), manager("bob")
    s1, s2 = run_handshake(alice, bob)

    assert s1.peer.signing_public == bob.identity.signing_public
    assert s2.peer.signing_public == alice.identity.signing_public
    assert s1.peer.static_public == bob.identity.static_public
    assert s2.peer.static_public == alice.identity.static_public


def test_signature_from_another_session_is_rejected():
    """A signature lifted from one handshake must not validate in another.

    This is the replay half of the impersonation attack: capture a real
    identity proof, then present it as your own in a fresh session.
    """
    # Capture a genuine handshake response from bob.
    alice, bob = manager("alice"), manager("bob")
    init_payload, _ = alice.start_handshake(bob.identity.static_public)
    genuine_response = bob.handle_init(init_payload)
    assert genuine_response is not None

    # Mallory opens her own handshake to bob and splices in bob's captured
    # response, keeping her own handshake ID so it correlates.
    mallory = manager("mallory")
    mallory_init, _ = mallory.start_handshake(bob.identity.static_public)
    hs_id = mallory_init[:4]
    replayed = hs_id + genuine_response[4:]

    # The ephemeral in the captured response was bound to alice's transcript,
    # not mallory's, so the AEAD over the static key fails outright.
    with pytest.raises((SessionError, NoiseError)):
        mallory.handle_response(replayed)


def test_forged_identity_signature_aborts_handshake(monkeypatch):
    """A valid Noise handshake with a bogus identity proof must still fail."""
    import chatbit.session as session_mod

    alice, bob = manager("alice"), manager("bob")
    mallory_identity = Identity.generate("mallory")

    real_encode = session_mod._encode_identity_payload

    def tampered(identity, handshake_hash, ratchet_pub):
        # Claim mallory's identity key while signing with bob's -- i.e. present
        # a key you do not control.
        blob = real_encode(identity, handshake_hash, ratchet_pub)
        return mallory_identity.signing_public + blob[32:]

    init_payload, _ = alice.start_handshake(bob.identity.static_public)
    monkeypatch.setattr(session_mod, "_encode_identity_payload", tampered)
    resp = bob.handle_init(init_payload)
    monkeypatch.undo()

    assert resp is not None
    with pytest.raises(SessionError, match="signature is invalid"):
        alice.handle_response(resp)


def test_mitm_produces_different_safety_numbers():
    """A relay that terminates both sides cannot make the numbers agree.

    Mallory runs a full handshake with Alice and another with Bob. Both
    succeed -- nothing stops someone from talking to you -- but Alice's number
    for her peer and Bob's number for his peer differ, which is exactly what
    the out-of-band comparison is for.
    """
    alice, bob, mallory = manager("alice"), manager("bob"), manager("mallory")

    a_side, m_side_a = run_handshake(alice, mallory)
    b_side, m_side_b = run_handshake(bob, mallory)

    alice_sees = safety_number(alice.identity.fingerprint, a_side.peer.fingerprint)
    bob_sees = safety_number(bob.identity.fingerprint, b_side.peer.fingerprint)
    genuine = safety_number(alice.identity.fingerprint, bob.identity.fingerprint)

    assert alice_sees != bob_sees
    assert alice_sees != genuine
    assert bob_sees != genuine


# ---------------------------------------------------------------------------
# trust pinning
# ---------------------------------------------------------------------------


def test_changed_static_key_is_refused_not_silently_accepted():
    trust = TrustStore(None)
    victim = Identity.generate("victim")
    trust.observe(victim.signing_public, victim.static_public, "victim")

    impostor_static = x25519_public_bytes(generate_x25519())
    with pytest.raises(KeyChangedError):
        trust.observe(victim.signing_public, impostor_static, "victim")


def test_nickname_is_never_an_identifier():
    """Two peers may share a nickname; lookup must not collapse them."""
    trust = TrustStore(None)
    real = Identity.generate("alice")
    impostor = Identity.generate("alice")

    trust.observe(real.signing_public, real.static_public, "alice")
    trust.observe(impostor.signing_public, impostor.static_public, "alice")

    matches = trust.by_nickname("alice")
    assert len(matches) == 2
    assert {m.signing_public for m in matches} == {
        real.signing_public,
        impostor.signing_public,
    }
    # Distinct fingerprints is what makes them distinguishable to a user.
    assert matches[0].fingerprint != matches[1].fingerprint


def test_impostor_cannot_inherit_verified_status():
    trust = TrustStore(None)
    real = Identity.generate("alice")
    trust.observe(real.signing_public, real.static_public, "alice")
    trust.mark_verified(real.signing_public)

    impostor = Identity.generate("alice")
    peer = trust.observe(impostor.signing_public, impostor.static_public, "alice")
    assert peer.verified is False
    assert trust.get(real.signing_public).verified is True


def test_repin_clears_verification():
    trust = TrustStore(None)
    peer_id = Identity.generate("bob")
    trust.observe(peer_id.signing_public, peer_id.static_public, "bob")
    trust.mark_verified(peer_id.signing_public)

    new_static = x25519_public_bytes(generate_x25519())
    peer = trust.repin(peer_id.signing_public, new_static)
    assert peer.verified is False, "re-pinning must not carry verified status over"


# ---------------------------------------------------------------------------
# ratchet robustness
# ---------------------------------------------------------------------------


def _ratchet_pair():
    sk = b"\x11" * 32
    bob_ratchet = generate_x25519()
    a = DoubleRatchet.init_sender(sk, x25519_public_bytes(bob_ratchet))
    b = DoubleRatchet.init_receiver(sk, bob_ratchet)
    return a, b


def test_forged_frame_does_not_desynchronise_session():
    """Anyone can transmit. A forgery must not break a healthy session."""
    a, b = _ratchet_pair()
    header, ct = a.encrypt(b"genuine")

    corrupted = ct[:-1] + bytes([ct[-1] ^ 0x01])
    with pytest.raises(RatchetError):
        b.decrypt(header, corrupted)

    assert b.decrypt(header, ct) == b"genuine"


def test_forged_ratchet_header_does_not_advance_state():
    a, b = _ratchet_pair()
    header, ct = a.encrypt(b"genuine")

    bogus = MessageHeader(x25519_public_bytes(generate_x25519()), 0, 0)
    with pytest.raises(RatchetError):
        b.decrypt(bogus, ct)

    assert b.decrypt(header, ct) == b"genuine"


def test_replay_is_rejected():
    a, b = _ratchet_pair()
    header, ct = a.encrypt(b"once")
    assert b.decrypt(header, ct) == b"once"
    with pytest.raises(RatchetError):
        b.decrypt(header, ct)


def test_skip_limit_bounds_work_from_one_frame():
    a, b = _ratchet_pair()
    a.ns = 10**6  # attacker claims an enormous counter
    header, ct = a.encrypt(b"far future")
    with pytest.raises(RatchetError):
        b.decrypt(header, ct)


def test_post_compromise_security_heals_session():
    """After a full state compromise, the session recovers.

    Healing takes two round trips: the compromised side mints a new ratchet key
    while processing the peer's next message, and the peer must then adopt it.
    Messages before that point remain readable to the attacker, by design.
    """
    a, b = _ratchet_pair()
    header, ct = a.encrypt(b"warmup")
    b.decrypt(header, ct)

    leaked = DoubleRatchet.deserialize(b.serialize())

    def attacker_can_read(header, ct) -> bool:
        clone = DoubleRatchet.deserialize(leaked.serialize())
        try:
            clone.decrypt(header, ct)
            return True
        except RatchetError:
            return False

    # Immediately after compromise the attacker reads everything.
    header, ct = a.encrypt(b"m1")
    assert attacker_can_read(header, ct)
    b.decrypt(header, ct)

    # Two round trips later it cannot.
    for body in (b"m2", b"m3", b"m4"):
        h, c = b.encrypt(body)
        a.decrypt(h, c)
        h, c = a.encrypt(body + b"-reply")
        b.decrypt(h, c)

    header, ct = a.encrypt(b"post-healing secret")
    assert not attacker_can_read(header, ct)
    assert b.decrypt(header, ct) == b"post-healing secret"


def test_forward_secrecy_current_state_cannot_open_past_messages():
    """Seizing a device must not retroactively decrypt recorded traffic.

    Note what this does *not* claim. Within a single sending chain, a captured
    chain key derives every *later* key in that chain -- chain keys only
    ratchet forward. Recovery from that needs a DH ratchet step, which is
    post-compromise security and is tested separately. Forward secrecy is the
    backward-looking property: keys held now do not open messages already sent.
    """
    a, b = _ratchet_pair()

    recorded = [a.encrypt(f"historic {i}".encode()) for i in range(5)]
    for header, ct in recorded:
        b.decrypt(header, ct)

    # Attacker seizes Bob's device here and gets his complete current state.
    seized = DoubleRatchet.deserialize(b.serialize())

    for header, ct in recorded:
        with pytest.raises(RatchetError):
            seized.decrypt(header, ct)


# ---------------------------------------------------------------------------
# handshake state machine
# ---------------------------------------------------------------------------


def test_low_order_point_is_rejected():
    """A degenerate DH must abort rather than yield a predictable secret."""
    bob = manager("bob")
    resp = bob.handle_init(b"\x00\x00\x00\x00" + b"\x00" * 32)
    assert resp is None


def test_out_of_order_handshake_messages_are_rejected():
    alice = Identity.generate("alice")
    hs = HandshakeState(initiator=True, static_private=alice.static_private, prologue=PROLOGUE)
    with pytest.raises(NoiseError):
        hs.write_message_3(lambda h: b"")


def test_pending_handshakes_are_bounded():
    """A handshake flood must not grow state without bound."""
    bob = manager("bob")
    for _ in range(200):
        alice = manager("attacker")
        payload, _ = alice.start_handshake(bob.identity.static_public)
        bob.handle_init(payload)
    assert bob.pending_count <= 32
