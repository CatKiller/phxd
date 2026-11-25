"""Fuzzing: random and malformed Hotline packets and IRC lines, before and
after login, from several clients at once. The server must not hit any
unhandled exception, must not disconnect bystanders, and must keep
working for new clients."""
import random, struct
from shared import HLProtocol as P
from tests.irc_harness import irc_server  # noqa: F401

TYPES = [v for k, v in vars(P).items() if k.startswith("HTLC_HDR_")] + [0, 1, 0xFFFF, 0x10000]
FIELDS = [v for k, v in vars(P).items() if k.startswith("DATA_")]

def rand_obj(rng):
    t = rng.choice(FIELDS + [rng.randrange(0x10000)])
    n = rng.choice([0, 1, 2, 3, 4, 8, 16, 100, 2000])
    data = bytes(rng.randrange(256) for _ in range(n))
    if rng.random() < 0.2:
        data = b"\x00\x02\x00\x00\x02..\x00\x00\x03../" + data
    return t, data

def run(irc_server, seed):
    rng = random.Random(seed)
    unhandled = []
    real_exc = irc_server.server.log.exception
    irc_server.server.log.exception = lambda msg, *a, **k: (unhandled.append(msg % a), real_exc(msg, *a, **k))
    bystander = irc_server.hotline_client(host="10.99.%d.1" % seed)
    bystander.login("guest", "", "bystander")
    clients = []
    for i in range(6):
        host = "10.0.%d.%d" % (seed % 250, i)
        c = irc_server.hotline_client(host=host) if i % 2 else irc_server.irc_client(host=host)
        if i % 3 == 0:
            if i % 2:
                c.login("guest", "", "fz%d" % i)
            else:
                c.send("NICK fz%d" % i, "USER a 0 * :a", "PRIVMSG loginserv guest")
        clients.append(c)
    for _ in range(400):
        c = rng.choice(clients)
        if c.closed:
            continue
        if hasattr(c, "send_packet"):
            objs = [rand_obj(rng) for _ in range(rng.randrange(6))]
            body = struct.pack("!H", len(objs)) + b"".join(struct.pack("!2H", t, len(d)) + d for t, d in objs)
            if rng.random() < 0.1:
                body = bytes(rng.randrange(256) for _ in range(rng.randrange(40)))
            hdr = struct.pack("!5L", rng.choice(TYPES), rng.randrange(1 << 32), rng.randrange(4), len(body), len(body))
            c.conn.dataReceived(hdr + body)
        else:
            words = ["PRIVMSG", "NICK", "JOIN", "PART", "KICK", "INVITE", "WHOIS", "WHO", "PING", "MODE", "QUIT",
                     "NICKSERV", "PASS", "CAP", "#public", "#1", "#x", "loginserv", "1_x", ":", "!test", "/me", "/0wn 1 name x",
                     "/find", "/color 65535", "\x00", "\xff", "a" * 300]
            line = " ".join(rng.choice(words) for _ in range(rng.randrange(1, 6)))
            c.send_raw(line.encode("mac-roman", "replace") + b"\r\n")
        irc_server.clock.advance(rng.choice([0, 0, 0, 1, 7]))
    assert not bystander.closed, "a bystander was disconnected"
    fresh = irc_server.hotline_client(host="10.98.%d.1" % seed)
    fresh.login("tester", "s3cret", "fresh")
    assert fresh.user.isLoggedIn()
    fresh.send_packet(P.HTLC_HDR_CHAT, [(P.DATA_STRING, b"still alive")])
    assert b"still alive" in bystander.transport.data
    return unhandled

def test_fuzz(irc_server):
    unhandled = []
    for seed in range(10):
        unhandled += run(irc_server, seed)
        irc_server.clock.advance(120)
    assert unhandled == []
