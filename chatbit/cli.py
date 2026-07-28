"""Command-line interface.

    chatbit id                 show your identity and fingerprint
    chatbit regions            list band plans and their limits
    chatbit plan               what your radio config actually buys you
    chatbit peers              list known peers, verify one
    chatbit demo               run a mesh in-process, no hardware needed
    chatbit chat               interactive chat over UDP or a LoRa radio
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import getpass
import os
import sys
from pathlib import Path

from .config import MeshConfig, NodeConfig, RadioConfig
from .crypto.identity import Identity, TrustStore, format_fingerprint, safety_number
from .node import IncomingMessage, Node
from .radio.airtime import bitrate, time_on_air
from .radio.base import Transport
from .radio.loopback import LoopbackTransport, Medium
from .radio.regions import REGIONS, RegionError, get_region
from .radio.udp import UDPMulticastTransport
from .wire.packet import HEADER_LEN
from .wire.padding import PaddingPolicy, padded_size

BANNER = r"""
      _           _   _     _ _
  ___| |__   __ _| |_| |__ (_) |_
 / __| '_ \ / _` | __| '_ \| | __|   encrypted mesh chat
| (__| | | | (_| | |_| |_) | | |_    on radio you control
 \___|_| |_|\__,_|\__|_.__/|_|\__|
"""


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def resolve_passphrase(path: Path, args) -> str | None:
    """Work out the passphrase for an identity file, prompting if needed.

    The passphrase is deliberately **not** accepted as a command-line argument.
    Anything on argv is visible to every other process on the machine via `ps`
    and lands in shell history, which would make the option actively worse than
    having none. It comes from an environment variable or an interactive
    prompt, and nowhere else.
    """
    env_var = getattr(args, "passphrase_env", None) or "CHATBIT_PASSPHRASE"
    from_env = os.environ.get(env_var)
    if from_env:
        return from_env

    exists = path.exists()

    if exists and Identity.is_encrypted(path):
        if not sys.stdin.isatty():
            raise SystemExit(
                f"{path} is encrypted and there is no terminal to prompt on.\n"
                f"Set {env_var} in the environment instead."
            )
        return getpass.getpass(f"passphrase for {path}: ")

    if exists:
        return None  # existing, unencrypted: nothing to ask

    # Creating a new identity. This is the one moment we can offer encryption,
    # so take it rather than silently writing a private key in the clear.
    if getattr(args, "no_encrypt", False):
        print(f"!! creating an UNENCRYPTED identity at {path}", file=sys.stderr)
        return None

    if not sys.stdin.isatty():
        print(
            f"!! creating an UNENCRYPTED identity at {path} (no terminal to "
            f"prompt on; set {env_var} to encrypt it)",
            file=sys.stderr,
        )
        return None

    print(f"Creating a new identity at {path}.")
    print("A passphrase encrypts the private keys at rest. Empty means no encryption.")
    first = getpass.getpass("passphrase (empty to skip): ")
    if not first:
        print("!! identity will be stored UNENCRYPTED", file=sys.stderr)
        return None
    second = getpass.getpass("confirm: ")
    if first != second:
        raise SystemExit("passphrases did not match")
    return first


def load_identity(args) -> Identity:
    path = Path(args.identity).expanduser()
    passphrase = resolve_passphrase(path, args)
    try:
        return Identity.load_or_create(path, args.nick, passphrase)
    except Exception as exc:
        # A wrong passphrase surfaces as an AEAD failure, which is accurate but
        # unhelpful as a first line of output.
        if path.exists() and Identity.is_encrypted(path):
            raise SystemExit(f"could not unlock {path}: wrong passphrase?") from exc
        raise


def build_config(args) -> NodeConfig:
    config = NodeConfig(
        nickname=args.nick,
        identity_path=args.identity,
        trust_path=args.trust,
        transport=args.transport,
        radio=RadioConfig(
            region=args.region,
            frequency_hz=int(args.freq * 1e6),
            spreading_factor=args.sf,
            bandwidth_hz=int(args.bw * 1000),
            coding_rate=args.cr,
            tx_power_dbm=args.power,
            mtu=args.mtu,
        ),
        mesh=MeshConfig(
            padding=PaddingPolicy(args.padding),
            cover_traffic=args.cover,
            default_ttl=args.ttl,
        ),
        serial_port=args.port,
        serial_baud=args.baud,
        udp_group=args.group,
        udp_port=args.udp_port,
    )
    return config


def build_transport(config: NodeConfig, driver: str = "rylr") -> Transport:
    if config.transport == "lora":
        from .radio.lora import LoRaTransport

        return LoRaTransport(
            config.radio,
            port=config.serial_port,
            baud=config.serial_baud,
            driver=driver,
        )
    if config.transport == "udp":
        return UDPMulticastTransport(
            group=config.udp_group, port=config.udp_port, mtu=config.radio.mtu
        )
    raise SystemExit(f"transport {config.transport!r} is not usable from the CLI")


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def cmd_id(args) -> int:
    identity = load_identity(args)
    print(BANNER)
    print(f"nickname     {identity.nickname}")
    print(f"short id     {identity.short_id}")
    print(f"fingerprint  {format_fingerprint(identity.fingerprint)}")
    print(f"identity key {identity.signing_public.hex()}")
    print(f"static key   {identity.static_public.hex()}")
    print()
    print("Share the static key with a peer so they can start a handshake:")
    print(f"  chatbit chat --connect {identity.static_public.hex()}")
    return 0


def cmd_regions(args) -> int:
    for region in REGIONS.values():
        print(region.describe())
        print()
    return 0


def cmd_plan(args) -> int:
    """Airtime budget for a radio config.

    Worth running before you commit to settings. LoRa's range comes from
    spending time on air, and time on air is the resource the regulator caps.
    """
    try:
        radio = RadioConfig(
            region=args.region,
            frequency_hz=int(args.freq * 1e6),
            spreading_factor=args.sf,
            bandwidth_hz=int(args.bw * 1000),
            coding_rate=args.cr,
            tx_power_dbm=args.power,
            mtu=args.mtu,
        )
        radio.validate()
    except RegionError as exc:
        print(f"invalid configuration: {exc}", file=sys.stderr)
        return 1

    plan = radio.region_plan()
    policy = PaddingPolicy(args.padding)
    print(BANNER)
    print(radio.summary())
    print()
    print(plan.describe())
    print()

    # A short text message, once encrypted and framed.
    typical_payload = 40 + 40  # ratchet header + a line of text, ciphertext
    frame = HEADER_LEN + typical_payload
    on_air = padded_size(frame, radio.mtu, policy)
    toa = radio.airtime_for(on_air)

    print(f"padding policy: {policy.value}")
    print(f"  a one-line message occupies {on_air} B on air, {toa * 1000:.0f} ms")

    warnings: list[str] = []

    if plan.max_dwell_ms is not None and toa * 1000 > plan.max_dwell_ms:
        warnings.append(
            f"Time on air ({toa * 1000:.0f} ms) exceeds the {plan.name} dwell limit "
            f"of {plan.max_dwell_ms:.0f} ms. This configuration is not usable there.\n"
            f"    Lower the spreading factor, widen the bandwidth, or reduce the MTU."
        )

    if plan.duty_cycle is not None:
        gap = toa / plan.duty_cycle
        per_hour = int(3600 / gap) if gap > 0 else 0
        print(
            f"  duty cycle {plan.duty_cycle:.0%} forces a {gap:.0f} s gap between "
            f"frames -> about {per_hour} frames/hour"
        )
        # A handshake is 4 logical messages; the 224-byte Noise message 2
        # fragments into two frames at a typical MTU.
        handshake_frames = 5
        print(
            f"  a handshake is ~{handshake_frames} frames, so roughly "
            f"{handshake_frames * gap / 60:.1f} min to establish a session"
        )
        if policy is PaddingPolicy.STRICT and per_hour < 60:
            warnings.append(
                "STRICT padding pads every frame to the full MTU, which is what "
                "makes message length unobservable -- but it is expensive here.\n"
                f"    You get ~{per_hour} frames/hour. Consider --padding bucket, "
                "a lower SF, or a region without a duty cycle."
            )

    if warnings:
        print()
        for warning in warnings:
            print(f"  WARNING: {warning}")

    print()
    print("  range vs speed, at this bandwidth:")
    for sf in range(7, 13):
        t = time_on_air(on_air, sf, radio.bandwidth_hz, radio.coding_rate)
        gap = f"{t / plan.duty_cycle:6.0f} s" if plan.duty_cycle else "     --"
        dwell = ""
        if plan.max_dwell_ms is not None and t * 1000 > plan.max_dwell_ms:
            dwell = "  over dwell limit"
        marker = " <-" if sf == radio.spreading_factor else "   "
        print(
            f"    SF{sf:<3} {bitrate(sf, radio.bandwidth_hz, radio.coding_rate):6.0f} bit/s   "
            f"{t * 1000:7.0f} ms/frame   gap {gap}{marker}{dwell}"
        )
    return 0


def cmd_peers(args) -> int:
    identity = load_identity(args)
    trust = TrustStore(Path(args.trust).expanduser())

    if args.verify:
        peer = trust.by_short_id(args.verify)
        if peer is None:
            print(f"no peer with short id {args.verify!r}", file=sys.stderr)
            return 1
        number = safety_number(identity.fingerprint, peer.fingerprint)
        print(f"Safety number with {peer.nickname or peer.short_id}#{peer.short_id}:")
        print(f"\n    {number}\n")
        print("Compare this with the other person over a channel you already trust")
        print("(in person, or a voice call where you recognise their voice).")
        print("It must match exactly, digit for digit.")
        answer = input("\nDoes it match? [y/N] ").strip().lower()
        if answer == "y":
            trust.mark_verified(peer.signing_public)
            print(f"marked {peer.short_id} as verified")
        else:
            print("left unverified. Do not treat this session as authenticated.")
        return 0

    peers = trust.all()
    if not peers:
        print("no known peers yet")
        return 0
    print(f"{'short':8} {'nick':16} {'status':12} fingerprint")
    for peer in peers:
        status = "verified" if peer.verified else "UNVERIFIED"
        print(
            f"{peer.short_id:8} {(peer.nickname or '-')[:16]:16} {status:12} "
            f"{format_fingerprint(peer.fingerprint, groups=4)}"
        )
    return 0


async def _run_demo(count: int, loss: float) -> None:
    """Spin up a chain of nodes in-process and pass a message end to end."""
    medium = Medium(loss=loss)
    names = [f"node{i}" for i in range(count)]
    # A line topology, so the message has to be relayed hop by hop.
    medium.topology = {
        name: {n for n in (names[i - 1] if i else None, names[i + 1] if i + 1 < count else None) if n}
        for i, name in enumerate(names)
    }

    nodes: list[Node] = []
    inboxes: dict[str, list[IncomingMessage]] = {n: [] for n in names}

    def make_handler(name: str):
        async def handler(message: IncomingMessage) -> None:
            inboxes[name].append(message)
            print(f"  [{name}] <- {message.display_name}: {message.text}")

        return handler

    for name in names:
        config = NodeConfig(
            nickname=name,
            transport="loopback",
            mesh=MeshConfig(relay_jitter_min=0.01, relay_jitter_max=0.05),
        )
        node = Node(
            config=config,
            transport=LoopbackTransport(medium, name=name, mtu=200),
            identity=Identity.generate(name),
            trust=TrustStore(None),
            on_message=make_handler(name),
            on_event=lambda msg, n=name: print(f"  [{n}] {msg}"),
        )
        nodes.append(node)
        await node.start()

    print(f"\n{count} nodes in a line: {' -- '.join(names)}")
    print(f"only adjacent nodes can hear each other (loss {loss:.0%})\n")

    first, last = nodes[0], nodes[-1]
    print(f"{names[0]} -> {names[-1]}: handshake across {count - 1} hops")
    for attempt in range(8):
        await first.connect(last.identity.static_public)
        await asyncio.sleep(0.6)
        if first.sessions.session_for(last.identity.signing_public):
            break
    else:
        print("handshake did not complete -- try a lower loss rate")
        for node in nodes:
            await node.stop()
        return

    print("\nsending a message end to end")
    await first.send_text(last.identity.signing_public, "hello from the far end")
    await asyncio.sleep(1.0)

    print("\nrelay nodes in the middle forwarded traffic they could not read:")
    for node, name in zip(nodes, names):
        stats = node.router.stats
        print(
            f"  {name:8} relayed {stats.relayed:3}  received {stats.received:3}  "
            f"delivered locally {stats.delivered_local:3}  "
            f"plaintext seen: {len(inboxes[name])}"
        )

    for node in nodes:
        await node.stop()


def cmd_demo(args) -> int:
    print(BANNER)
    asyncio.run(_run_demo(args.nodes, args.loss))
    return 0


async def _run_chat(args) -> None:
    config = build_config(args)
    try:
        config.validate()
    except (RegionError, ValueError) as exc:
        raise SystemExit(f"invalid configuration: {exc}")

    identity = load_identity(args)
    trust = TrustStore(Path(args.trust).expanduser())
    transport = build_transport(config, driver=args.driver)

    def on_event(message: str) -> None:
        print(f"\r-- {message}")

    async def on_message(message: IncomingMessage) -> None:
        print(f"\r<{message.display_name}> {message.text}")

    node = Node(
        config=config,
        transport=transport,
        identity=identity,
        trust=trust,
        on_message=on_message,
        on_event=on_event,
    )

    print(BANNER)
    print(f"you are {identity.nickname}#{identity.short_id}")
    print(f"fingerprint {format_fingerprint(identity.fingerprint)}")
    if config.transport == "lora":
        print(config.radio.summary())
    print("\ncommands: /peers  /connect <statickey>  /verify <shortid>  "
          "/status  /quit\n")

    await node.start()
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    await loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(reader), sys.stdin
    )

    if args.connect:
        await node.connect(bytes.fromhex(args.connect))
        print("-- handshake sent")

    target: bytes | None = None
    try:
        while True:
            line = (await reader.readline()).decode().strip()
            if not line:
                continue

            if line.startswith("/"):
                parts = line.split()
                command = parts[0]
                if command in ("/quit", "/q"):
                    break
                elif command == "/status":
                    print(node.status())
                elif command == "/peers":
                    for peer in node.trust.all():
                        mark = "verified" if peer.verified else "UNVERIFIED"
                        active = (
                            "session"
                            if node.sessions.session_for(peer.signing_public)
                            else "-"
                        )
                        print(
                            f"  {peer.short_id}  {peer.nickname or '-':16} "
                            f"{mark:11} {active}"
                        )
                    for peer in node.discovered.values():
                        if node.trust.get(peer.signing_public) is None:
                            print(
                                f"  {peer.short_id}  {peer.nickname or '-':16} "
                                f"discovered   static={peer.static_public.hex()[:16]}..."
                            )
                elif command == "/connect" and len(parts) > 1:
                    await node.connect(bytes.fromhex(parts[1]))
                    print("-- handshake sent")
                elif command == "/verify" and len(parts) > 1:
                    peer = node.trust.by_short_id(parts[1])
                    if peer is None:
                        print("-- no such peer")
                    else:
                        print(f"-- safety number: {node.safety_number_with(peer.signing_public)}")
                        print("-- compare out of band, then: chatbit peers --verify "
                              f"{peer.short_id}")
                elif command == "/to" and len(parts) > 1:
                    peer = node.trust.by_short_id(parts[1])
                    target = peer.signing_public if peer else None
                    print(f"-- talking to {parts[1]}" if target else "-- no such peer")
                else:
                    print("-- unknown command")
                continue

            sessions = node.sessions.sessions()
            recipient = target or (sessions[0].peer.signing_public if sessions else None)
            if recipient is None:
                print("-- no session yet; use /connect <statickey>")
                continue
            if not await node.send_text(recipient, line):
                print("-- send failed: no session with that peer")
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        await node.stop()


def cmd_chat(args) -> int:
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_run_chat(args))
    return 0


# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------


class _RejectPassphraseFlag(argparse.Action):
    """Refuse ``--passphrase``, loudly, instead of doing something worse.

    This option exists only to be rejected. Without it, argparse's prefix
    matching quietly resolves ``--passphrase hunter2`` to ``--passphrase-env``,
    so the secret becomes an *environment variable name*, no such variable
    exists, and the identity is written unencrypted -- while the passphrase
    itself sits in argv where `ps` and shell history can read it. Silently
    doing the opposite of what the user asked is the worst available outcome,
    so the flag is declared and refused.
    """

    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs="?", **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        parser.error(
            "--passphrase is not supported: anything on the command line is "
            "visible to other users via `ps` and is saved in shell history.\n"
            "Set the passphrase in an environment variable instead:\n"
            "    CHATBIT_PASSPHRASE=... chatbit ...\n"
            "or omit it and you will be prompted."
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chatbit", description="Encrypted mesh chat over radio you control."
    )
    parser.add_argument("--identity", default="~/.chatbit/identity.json")
    parser.add_argument("--trust", default="~/.chatbit/trust.json")
    parser.add_argument("--nick", default="anon")
    parser.add_argument(
        "--passphrase-env",
        default="CHATBIT_PASSPHRASE",
        metavar="VAR",
        help=(
            "environment variable holding the identity passphrase. There is "
            "deliberately no --passphrase flag: argv is world-readable via ps "
            "and lands in shell history."
        ),
    )
    parser.add_argument(
        "--no-encrypt",
        action="store_true",
        help="create a new identity without a passphrase, without prompting",
    )
    # Declared solely so it can be refused with a useful message; see the
    # action's docstring for why leaving it undeclared is unsafe.
    parser.add_argument("--passphrase", action=_RejectPassphraseFlag, help=argparse.SUPPRESS)

    sub = parser.add_subparsers(dest="command", required=True)

    def add_radio_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--region", default="EU868", help="band plan, see `chatbit regions`")
        p.add_argument("--freq", type=float, default=868.1, help="frequency in MHz")
        p.add_argument("--sf", type=int, default=9, help="spreading factor 7-12")
        p.add_argument("--bw", type=float, default=125, help="bandwidth in kHz")
        p.add_argument("--cr", type=int, default=5, help="coding rate denominator, 4/n")
        p.add_argument("--power", type=int, default=14, help="TX power in dBm")
        p.add_argument("--mtu", type=int, default=200, help="bytes per frame")
        p.add_argument(
            "--padding",
            default="strict",
            choices=[p.value for p in PaddingPolicy],
            help="length-hiding policy",
        )

    p_id = sub.add_parser("id", help="show your identity")
    p_id.set_defaults(func=cmd_id)

    p_regions = sub.add_parser("regions", help="list band plans")
    p_regions.set_defaults(func=cmd_regions)

    p_plan = sub.add_parser("plan", help="airtime budget for a radio config")
    add_radio_args(p_plan)
    p_plan.set_defaults(func=cmd_plan)

    p_peers = sub.add_parser("peers", help="list known peers")
    p_peers.add_argument("--verify", metavar="SHORTID", help="verify a peer's safety number")
    p_peers.set_defaults(func=cmd_peers)

    p_demo = sub.add_parser("demo", help="run a mesh in-process, no hardware")
    p_demo.add_argument("--nodes", type=int, default=4)
    p_demo.add_argument("--loss", type=float, default=0.0)
    p_demo.set_defaults(func=cmd_demo)

    p_chat = sub.add_parser("chat", help="interactive chat")
    add_radio_args(p_chat)
    p_chat.add_argument("--transport", default="udp", choices=["udp", "lora"])
    p_chat.add_argument("--driver", default="rylr", choices=["rylr", "slip"])
    p_chat.add_argument("--port", default="/dev/ttyUSB0", help="serial port")
    p_chat.add_argument("--baud", type=int, default=115200)
    p_chat.add_argument("--group", default="239.23.23.23")
    p_chat.add_argument("--udp-port", type=int, default=4242)
    p_chat.add_argument("--ttl", type=int, default=7)
    p_chat.add_argument("--cover", action="store_true", help="enable cover traffic")
    p_chat.add_argument("--connect", metavar="HEX", help="peer static key to handshake with")
    p_chat.set_defaults(func=cmd_chat)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
