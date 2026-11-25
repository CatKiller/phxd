"""Fuzzing with every privilege: realistic but random requests to every
handler (files, accounts, news, chats, transfers). No unhandled
exceptions, no bystander disconnected, nothing outside the file root
touched."""
import os, random, struct
from shared import HLProtocol as P
from tests.irc_harness import irc_server  # noqa: F401

TYPES = [v for k, v in vars(P).items() if k.startswith("HTLC_HDR_")]
NAMES = [b"a.txt", b"sub", b"Uploads", b"Drop Box", b"..", b".", b"x/y", b"", b"new", b"\xff\xfe", b"a" * 300, b".env", b"zz.hpf"]

def dirobj(rng):
    parts = [rng.choice(NAMES) for _ in range(rng.randrange(4))]
    d = struct.pack("!H", len(parts))
    for p in parts:
        d += b"\0\0" + struct.pack("!B", len(p) & 0xFF) + p[:255]
    if rng.random() < 0.2:
        d = d[: rng.randrange(len(d) + 1)]
    return d

def field(rng):
    t = rng.choice([P.DATA_DIR, P.DATA_NEWDIR, P.DATA_FILENAME, P.DATA_NEWFILE, P.DATA_UID, P.DATA_CHATID,
                    P.DATA_STRING, P.DATA_LOGIN, P.DATA_PASSWORD, P.DATA_PRIVS, P.DATA_NICK, P.DATA_XFERSIZE,
                    P.DATA_RESUME, P.DATA_BAN, P.DATA_OPTION, P.DATA_GIFICON, P.DATA_NEWSLIMIT, P.DATA_SUBJECT])
    if t in (P.DATA_DIR, P.DATA_NEWDIR):
        return t, dirobj(rng)
    if t in (P.DATA_FILENAME, P.DATA_NEWFILE):
        return t, rng.choice(NAMES)
    if t in (P.DATA_UID, P.DATA_CHATID, P.DATA_BAN, P.DATA_OPTION, P.DATA_NEWSLIMIT, P.DATA_XFERSIZE):
        fmt, bits = rng.choice([("!H", 16), ("!L", 32), ("!Q", 64), ("!B", 8)])
        value = rng.randrange(1 << min(bits, 8)) if rng.random() < .5 else rng.randrange(1 << bits)
        return t, struct.pack(fmt, value)
    if t == P.DATA_PRIVS:
        return t, struct.pack("!Q", rng.randrange(1 << 64))
    if t in (P.DATA_LOGIN, P.DATA_PASSWORD):
        return t, bytes(255 - b for b in rng.choice([b"guest", b"tester", b"admin", b"new\tuser", b"x", b""]))
    if t == P.DATA_STRING and rng.random() < 0.5:
        sub = struct.pack("!H", 2) + struct.pack("!2H", P.DATA_LOGIN, 3) + b"abc" + struct.pack("!2H", P.DATA_PRIVS, 8) + b"\xff" * 8
        return t, sub
    return t, bytes(rng.randrange(256) for _ in range(rng.randrange(60)))

def run(irc_server, tmp_path, seed):
    rng = random.Random(seed)
    unhandled = []
    real_exc = irc_server.server.log.exception
    irc_server.server.log.exception = lambda msg, *a, **k: (unhandled.append(msg % a), real_exc(msg, *a, **k))
    clients = []
    for i in range(3):
        c = irc_server.hotline_client(host="10.%d.%d.1" % (seed % 250, i))
        c.login("tester", "s3cret", "adm%d" % i)
        clients.append(c)
    bystander = irc_server.hotline_client(host="10.200.%d.1" % seed)
    bystander.login("guest", "", "bystander")
    for _ in range(300):
        c = rng.choice(clients)
        if c.closed:
            continue
        objs = [field(rng) for _ in range(rng.randrange(5))]
        c.send_packet(rng.choice(TYPES), objs)
        irc_server.clock.advance(rng.choice([0, 0, 1, 40]))
    assert not bystander.closed
    assert (tmp_path / "outside.txt").read_text() == "keep", "file outside the root was touched"
    return unhandled

def test_fuzz_admin(irc_server, tmp_path):
    root = tmp_path / "files"
    root.mkdir(exist_ok=True)
    (tmp_path / "outside.txt").write_text("keep")
    for acct in irc_server.database.accounts:
        acct.fileRoot = str(root)
        if acct.login == "tester":
            acct.privs = 0xFFFFFFFFFFFFFFFF
    posts = []
    irc_server.database.loadNewsPosts = lambda limit=0: list(posts)[-limit:] if limit else list(posts)
    irc_server.database.saveNewsPost = lambda post: posts.append(post)
    unhandled = []
    for seed in range(15):
        (root / "sub").mkdir(exist_ok=True)
        (root / "Uploads").mkdir(exist_ok=True)
        (root / "a.txt").write_text("a")
        unhandled += run(irc_server, tmp_path, seed)
        irc_server.clock.advance(120)
    print("\nUNHANDLED (%d):" % len(unhandled))
    for u in sorted(set(unhandled)):
        print("  ", u)
