"""Regression tests for the security fixes: chat commands never reach a
shell, file paths stay inside the file root, privileged chat commands check
privileges, transfers can't be claimed by others, abuse limits, and IRC
output can't be forged."""
from __future__ import annotations

import os
import stat
import struct

import pytest

from shared.HLProtocol import (
    DATA_CHATID,
    DATA_DIR,
    DATA_FILENAME,
    DATA_NICK,
    DATA_OPTION,
    DATA_STRING,
    DATA_XFERID,
    HTLC_HDR_CHAT,
    HTLC_HDR_FILE_GET,
    HTLC_HDR_FILE_GETINFO,
    HTLC_HDR_FILE_LIST,
    HTLC_HDR_USER_CHANGE,
    HTLS_HDR_TASK,
    PRIV_DOWNLOAD_FILES,
    PRIV_KICK_USERS,
    PRIV_SEND_CHAT,
    PRIV_USE_ANY_NAME,
    STATUS_ADMIN,
    cleanNick,
    ircText,
)
from shared.HLTypes import HLException
from tests.conftest import make_account
from tests.irc_harness import irc_server  # noqa: F401  (fixture)


def dir_object(*parts):
    """A DATA_DIR payload: count, then (2-byte reserved, 1-byte len, name)."""
    data = struct.pack("!H", len(parts))
    for part in parts:
        raw = part.encode("mac-roman")
        data += b"\0\0" + struct.pack("!B", len(raw)) + raw
    return data


def errors(client):
    """The DATA_ERROR texts of the TASK replies received since last call."""
    from shared.HLProtocol import DATA_ERROR, HLPacket

    data = client.transport.data[client._read :]
    client._read = len(client.transport.data)
    out = []
    pos = 0
    while pos + 20 <= len(data):
        packet = HLPacket()
        size = packet.parse(data[pos:])
        if size <= 0:
            break
        if packet.type == HTLS_HDR_TASK and packet.flags == 1:
            out.append(packet.getString(DATA_ERROR, ""))
        pos += size
    return out


# ---------------------------------------------------------------------------
# Chat commands and server-side scripts
# ---------------------------------------------------------------------------


@pytest.fixture
def exec_dir(tmp_path, monkeypatch):
    """A support/exec directory holding an ``echoargs`` script."""
    import shared.HLUtils as utils

    d = tmp_path / "exec"
    d.mkdir()
    script = d / "echoargs"
    script.write_text('#!/bin/sh\nfor a in "$@"; do printf "[%s]" "$a"; done\n')
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(utils, "EXEC_DIR", str(d))
    return d


class TestServerScripts:
    def test_arguments_are_not_interpreted_by_a_shell(self, irc_server, exec_dir, tmp_path):
        from shared.HLUtils import shell_exec

        client = irc_server.hotline_client()
        client.login("guest", "", "eve")
        marker = tmp_path / "marker"
        out = shell_exec(client.user, "echoargs", f"a;touch {marker} $(id)")
        assert out == f"[a;touch][{marker}][$(id)]"
        assert not marker.exists()

    @pytest.mark.parametrize("name", ["echoargs;id", "../echoargs", "echoargs ", "", "nope", "a/b"])
    def test_only_existing_scripts_by_plain_name_run(self, irc_server, exec_dir, name):
        from shared.HLUtils import shell_exec

        client = irc_server.hotline_client()
        client.login("guest", "", "eve")
        assert shell_exec(client.user, name, "") is None

    def test_unknown_chat_command_is_sent_as_chat(self, irc_server, exec_dir, tmp_path):
        watcher = irc_server.hotline_client()
        watcher.login("guest", "", "watcher")
        client = irc_server.hotline_client()
        client.login("guest", "", "eve")
        watcher.replies()
        marker = tmp_path / "marker2"
        client.send_packet(HTLC_HDR_CHAT, [(DATA_STRING, f"/;touch {marker}")])
        assert not marker.exists()
        # Not a command, so it went to public chat like any other line.
        assert f"touch {marker}".encode("mac-roman") in watcher.transport.data


# ---------------------------------------------------------------------------
# File paths
# ---------------------------------------------------------------------------


class TestBuildPath:
    @pytest.mark.parametrize(
        "dirs, name",
        [
            ([], "../secret"),
            ([], ".."),
            ([], "a/../../secret"),
            (["../.."], "secret"),
            (["sub", ".."], "x"),
            (["a/b"], "x"),
            (["."], "x"),
            ([], "x\0y"),
        ],
    )
    def test_rejects_escapes(self, tmp_path, dirs, name):
        from server.handlers.FileHandler import buildPath

        with pytest.raises(HLException):
            buildPath(str(tmp_path / "files"), dirs, name)

    def test_accepts_ordinary_names(self, tmp_path):
        from server.handlers.FileHandler import buildPath

        root = str(tmp_path / "files")
        assert buildPath(root, ["Uploads", "", "My Folder"], "file..name.txt") == os.sep.join(
            [root, "Uploads", "My Folder", "file..name.txt"]
        )
        assert buildPath(root, []) == root


@pytest.fixture
def file_root(irc_server, tmp_path):
    root = tmp_path / "files"
    (root / "Uploads").mkdir(parents=True)
    (root / "Drop Box").mkdir()
    (root / "Drop Box" / "private.txt").write_text("private")
    (root / "public.txt").write_text("public")
    (tmp_path / "outside.txt").write_text("outside")
    for acct in irc_server.database.accounts:
        acct.fileRoot = str(root)
    return root


class TestFileHandlers:
    def test_listing_outside_the_root_is_refused(self, irc_server, file_root):
        client = irc_server.hotline_client()
        client.login("guest", "", "eve")
        errors(client)
        client.send_packet(HTLC_HDR_FILE_LIST, [(DATA_DIR, dir_object(".."))])
        client.send_packet(HTLC_HDR_FILE_LIST, [(DATA_DIR, dir_object("../.."))])
        assert errors(client) == ["Invalid file or folder name."] * 2
        assert b"outside.txt" not in client.transport.data

    def test_download_outside_the_root_is_refused(self, irc_server, file_root):
        guest = next(a for a in irc_server.database.accounts if a.login == "guest")
        guest.privs |= PRIV_DOWNLOAD_FILES
        client = irc_server.hotline_client()
        client.login("guest", "", "eve")
        errors(client)
        client.send_packet(HTLC_HDR_FILE_GET, [(DATA_FILENAME, "../outside.txt")])
        assert errors(client) == ["Invalid file or folder name."]
        assert irc_server.server.fileserver.transfers == {}

    def test_drop_box_contents_are_hidden(self, irc_server, file_root):
        guest = next(a for a in irc_server.database.accounts if a.login == "guest")
        guest.privs |= PRIV_DOWNLOAD_FILES
        client = irc_server.hotline_client()
        client.login("guest", "", "eve")
        errors(client)
        client.send_packet(HTLC_HDR_FILE_GET, [(DATA_DIR, dir_object("Drop Box")), (DATA_FILENAME, "private.txt")])
        client.send_packet(HTLC_HDR_FILE_GETINFO, [(DATA_DIR, dir_object("Drop Box")), (DATA_FILENAME, "private.txt")])
        assert errors(client) == ["You are not allowed to view drop boxes."] * 2


# ---------------------------------------------------------------------------
# Privileged chat commands
# ---------------------------------------------------------------------------


class TestChatCommands:
    def test_0wn_needs_kick_privilege(self, irc_server):
        victim = irc_server.hotline_client()
        victim.login("guest", "", "victim")
        attacker = irc_server.hotline_client()
        attacker.login("guest", "", "eve")
        attacker.send_packet(HTLC_HDR_CHAT, [(DATA_STRING, f"/0wn {victim.uid} name pwned")])
        assert victim.user.nick == "victim"

    def test_0wn_works_for_moderators(self, irc_server):
        irc_server.database.accounts.append(
            make_account(login="mod", name="Mod", password="d41d8cd98f00b204e9800998ecf8427e",
                         privs=PRIV_KICK_USERS | PRIV_SEND_CHAT | PRIV_USE_ANY_NAME)
        )
        victim = irc_server.hotline_client()
        victim.login("guest", "", "victim")
        mod = irc_server.hotline_client()
        mod.login("mod", "", "mod")
        mod.send_packet(HTLC_HDR_CHAT, [(DATA_STRING, f"/0wn {victim.uid} name renamed")])
        assert victim.user.nick == "renamed"

    def test_color_cannot_set_admin_flag(self, irc_server):
        client = irc_server.hotline_client()
        client.login("guest", "", "eve")
        client.send_packet(HTLC_HDR_CHAT, [(DATA_STRING, "/color %d" % (STATUS_ADMIN | 4))])
        assert client.user.status & STATUS_ADMIN == 0
        assert client.user.status & 4


# ---------------------------------------------------------------------------
# Server linking
# ---------------------------------------------------------------------------


def test_link_port_only_listens_when_enabled(monkeypatch):
    from twisted.internet import reactor

    import server.HLServerLinkage as linkage

    calls = []
    monkeypatch.setattr(reactor, "listenTCP", lambda *args, **kwargs: calls.append(args))
    monkeypatch.setattr(linkage, "ENABLE_SERVER_LINKING", False)
    linkage.HLServerLinker(object())
    assert calls == []
    monkeypatch.setattr(linkage, "ENABLE_SERVER_LINKING", True)
    linkage.HLServerLinker(object())
    assert len(calls) == 1


# ---------------------------------------------------------------------------
# File transfers
# ---------------------------------------------------------------------------


class FakeXferTransport:
    def __init__(self, host):
        self.host = host
        self.closed = False
        self.producer = None

    def getPeer(self):
        class Peer:
            pass

        peer = Peer()
        peer.host = self.host
        return peer

    def loseConnection(self):
        self.closed = True

    def registerProducer(self, producer, streaming):
        self.producer = producer

    def write(self, data):
        pass


class TestTransfers:
    def _download(self, irc_server, file_root):
        guest = next(a for a in irc_server.database.accounts if a.login == "guest")
        guest.privs |= PRIV_DOWNLOAD_FILES
        client = irc_server.hotline_client(host="10.0.0.1")
        client.login("guest", "", "alice")
        client.send_packet(HTLC_HDR_FILE_GET, [(DATA_FILENAME, "public.txt")])
        (xfer,) = irc_server.server.fileserver.transfers.values()
        return xfer

    def _connect(self, irc_server, host, xfid):
        from server.HLFileServer import HLTransferConnection

        conn = HLTransferConnection()
        conn.factory = irc_server.server.fileserver
        conn.makeConnection(FakeXferTransport(host))
        conn.dataReceived(struct.pack("!4L", 0x48545846, xfid, 0, 0))
        return conn

    def test_ids_are_not_sequential(self, irc_server):
        fs = irc_server.server.fileserver
        ids = {fs.newTransferID() for _ in range(50)}
        assert len(ids) == 50
        assert ids != set(range(min(ids), min(ids) + 50))

    def test_other_address_cannot_claim_transfer(self, irc_server, file_root):
        xfer = self._download(irc_server, file_root)
        thief = self._connect(irc_server, "10.6.6.6", xfer.id)
        assert thief.transport.closed
        assert thief.transport.producer is None
        owner = self._connect(irc_server, "10.0.0.1", xfer.id)
        assert owner.transport.producer is owner

    def test_transfer_cannot_be_claimed_twice(self, irc_server, file_root):
        xfer = self._download(irc_server, file_root)
        self._connect(irc_server, "10.0.0.1", xfer.id)
        second = self._connect(irc_server, "10.0.0.1", xfer.id)
        assert second.transport.closed
        assert second.transport.producer is None


# ---------------------------------------------------------------------------
# Abuse limits
# ---------------------------------------------------------------------------


class TestLimits:
    def test_oversized_packet_closes_connection(self, irc_server):
        client = irc_server.hotline_client()
        client.conn.dataReceived(struct.pack("!5L", HTLC_HDR_CHAT, 1, 0, 0xFFFFFFF0, 0xFFFFFFF0))
        assert client.closed

    def test_overlong_irc_line_closes_connection(self, irc_server):
        client = irc_server.irc_client()
        client.register("alice")
        client.send_raw(b"PRIVMSG #public :" + b"x" * 20000)
        assert client.closed

    def test_handshake_without_registration_is_bounded(self, irc_server):
        client = irc_server.irc_client()
        client.send_raw(b"CAP LS\r\n" * 2000)
        assert client.closed

    def test_irc_lines_split_across_writes(self, irc_server):
        client = irc_server.irc_client()
        client.register("alice")
        client.send_raw(b"PRIVMSG loginserv gu")
        client.send_raw(b"est\r\n")
        assert client.user.isLoggedIn()

    def test_login_timeout(self, irc_server):
        client = irc_server.hotline_client()
        irc_server.clock.advance(61)
        assert client.closed

    def test_logged_in_users_are_not_timed_out(self, irc_server):
        client = irc_server.hotline_client()
        client.login("guest", "", "alice")
        irc_server.clock.advance(61)
        assert not client.closed

    def test_repeated_failed_logins_ban_the_address(self, irc_server):
        for _ in range(5):
            client = irc_server.hotline_client(host="10.9.9.9")
            client.login("tester", "wrong")
            assert client.closed
        client = irc_server.hotline_client(host="10.9.9.9")
        client.login("tester", "s3cret")
        assert not client.user or not client.user.isLoggedIn()
        assert errors(client) == ["You are banned: Too many failed logins."]
        # Other addresses are unaffected.
        other = irc_server.hotline_client(host="10.1.1.1")
        other.login("tester", "s3cret")
        assert other.user.isLoggedIn()

    def test_connections_per_address_are_limited(self, irc_server):
        clients = [irc_server.irc_client(host="10.2.2.2") for _ in range(11)]
        assert [c.closed for c in clients] == [False] * 10 + [True]

    def test_failed_login_does_not_keep_account(self, irc_server):
        client = irc_server.irc_client()
        client.register("alice")
        client.send("PRIVMSG loginserv tester wrong")
        user = irc_server.server.getUser(client.uid)
        assert user is None or user.account is None


# ---------------------------------------------------------------------------
# Nicknames and IRC output
# ---------------------------------------------------------------------------


class TestIRCOutput:
    def test_clean_nick_and_irc_text(self):
        assert cleanNick("a\r\nPRIVMSG x\tb\0") == "aPRIVMSG xb"
        assert ircText("a\r\nb\0") == "a  b"

    def test_hotline_nick_cannot_inject_irc_lines(self, irc_server):
        from tests.test_irc import logged_in_irc_client

        watcher = logged_in_irc_client(irc_server)
        hl = irc_server.hotline_client()
        hl.login("guest", "", "eve")
        watcher.take()
        evil = "x\r\n:admin PRIVMSG #public :forged"
        hl.send_packet(HTLC_HDR_USER_CHANGE, [(DATA_NICK, evil)])
        # A second change keeping the same nick is shown as a status change
        # notice, which used to print the raw nick.
        hl.send_packet(HTLC_HDR_USER_CHANGE, [(DATA_NICK, evil)])
        hl.send_packet(HTLC_HDR_CHAT, [(DATA_STRING, "hi")])
        for line in watcher.take():
            assert not line.startswith(":admin")

    def test_who_hides_other_addresses(self, irc_server):
        from tests.test_irc import logged_in_irc_client

        watcher = logged_in_irc_client(irc_server)
        hl = irc_server.hotline_client(host="10.3.3.3")
        hl.login("guest", "", "eve")
        watcher.take()
        watcher.send("WHO #public")
        text = "\n".join(watcher.take())
        assert "10.3.3.3" not in text


# ---------------------------------------------------------------------------
# Second audit: scripts, uploads, /news
# ---------------------------------------------------------------------------


def test_exec_scripts_quote_user_data():
    """An unquoted $_VAR inside [ ] lets bash evaluate parts of the value
    (e.g. array subscripts with -v), i.e. run commands embedded in account
    data. Every reference to the user/account variables must be quoted."""
    import re

    exec_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "support", "exec")
    for name in os.listdir(exec_dir):
        path = os.path.join(exec_dir, name)
        if not os.path.isfile(path):
            continue
        for number, line in enumerate(open(path), 1):
            if line.lstrip().startswith("#"):
                continue
            # Inside [ ] or [[ ]], any $_VAR or $1 must be within double quotes.
            for test in re.findall(r"\[\[? (.*?) \]\]?", line):
                unquoted = re.sub(r'"[^"]*"', "", test)
                assert "$" not in unquoted, f"{name}:{number}: unquoted variable in test: {line.strip()}"


class TestUploadLimits:
    def _start_upload(self, irc_server, file_root, declared=0):
        from shared.HLProtocol import (
            DATA_XFERSIZE,
            HTLC_HDR_FILE_PUT,
            PRIV_UPLOAD_ANYWHERE,
            PRIV_UPLOAD_FILES,
        )

        guest = next(a for a in irc_server.database.accounts if a.login == "guest")
        guest.privs |= PRIV_UPLOAD_FILES | PRIV_UPLOAD_ANYWHERE
        client = irc_server.hotline_client(host="10.0.0.1")
        client.login("guest", "", "alice")
        objs = [(DATA_FILENAME, "up.bin")]
        if declared:
            objs.append((DATA_XFERSIZE, struct.pack("!L", declared)))
        client.send_packet(HTLC_HDR_FILE_PUT, objs)
        (xfer,) = irc_server.server.fileserver.transfers.values()
        return xfer

    def _connect(self, irc_server, xfid, size):
        from server.HLFileServer import HLTransferConnection

        conn = HLTransferConnection()
        conn.factory = irc_server.server.fileserver
        conn.makeConnection(FakeXferTransport("10.0.0.1"))
        conn.dataReceived(struct.pack("!4L", 0x48545846, xfid, size, 0))
        return conn

    def test_size_announced_late_is_checked_against_free_space(self, irc_server, file_root, monkeypatch):
        import shared.HLProtocol as proto

        xfer = self._start_upload(irc_server, file_root)
        monkeypatch.setattr(proto, "MIN_FREE_SPACE_MB", 1 << 40)
        conn = self._connect(irc_server, xfer.id, 1000)
        assert conn.transport.closed

    def test_no_more_than_the_announced_size_is_written(self, irc_server, file_root):
        from shared.HLProtocol import HLCharConst

        header = struct.pack("!LHLLLLH", HLCharConst("FILP"), 1, 0, 0, 0, 0, 1)
        fork = struct.pack("!4L", HLCharConst("DATA"), 0, 0, 0xFFFFFFFF)
        total = len(header) + len(fork) + 100
        xfer = self._start_upload(irc_server, file_root, declared=total)
        conn = self._connect(irc_server, xfer.id, total)
        conn.dataReceived(header + fork + b"x" * 5000)
        assert os.path.getsize(file_root / "up.bin") == 100


def test_news_command_needs_read_news(irc_server):
    from shared.HLProtocol import HTLS_HDR_MSG

    irc_server.database.loadNewsPosts = lambda limit: pytest.fail("news read without PRIV_READ_NEWS")
    client = irc_server.hotline_client()
    client.login("guest", "", "eve")
    client.send_packet(HTLC_HDR_CHAT, [(DATA_STRING, "/news")])


# ---------------------------------------------------------------------------
# Third pass: links out of the file root, XML-RPC and server linking
# ---------------------------------------------------------------------------


class TestLinksOutOfRoot:
    @pytest.fixture
    def linked_root(self, tmp_path):
        root = tmp_path / "files"
        root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("secret")
        (root / "inside.txt").write_text("inside")
        os.symlink(outside, root / "escape")
        os.symlink(outside / "secret.txt", root / "secret-link.txt")
        os.symlink(root / "inside.txt", root / "alias.txt")
        return root

    @pytest.mark.parametrize("dirs, name", [(["escape"], "secret.txt"), ([], "secret-link.txt"), (["escape"], "new.txt"), ([], "escape")])
    def test_links_leading_outside_are_refused(self, linked_root, dirs, name):
        from server.handlers.FileHandler import buildPath

        with pytest.raises(HLException):
            buildPath(str(linked_root), dirs, name)

    def test_links_inside_the_root_work(self, linked_root):
        from server.handlers.FileHandler import buildPath

        assert buildPath(str(linked_root), [], "alias.txt").endswith("alias.txt")

    def test_can_be_allowed(self, linked_root, monkeypatch):
        import server.handlers.FileHandler as fh

        monkeypatch.setattr(fh, "ALLOW_LINKS_OUTSIDE_FILE_ROOT", True)
        assert fh.buildPath(str(linked_root), ["escape"], "secret.txt").endswith("secret.txt")


def test_link_connections_only_from_allowed_hosts(monkeypatch):
    from twisted.internet import reactor

    import server.HLServerLinkage as linkage
    from tests.irc_harness import FakeAddress

    monkeypatch.setattr(reactor, "listenTCP", lambda *args, **kwargs: None)
    linker = linkage.HLServerLinker(object())
    assert linker.buildProtocol(FakeAddress("203.0.113.9")) is None
    assert linker.buildProtocol(FakeAddress("127.0.0.1")) is not None


def test_xmlrpc_listens_on_configured_interface(monkeypatch):
    from twisted.internet import reactor

    import server.HLWebServices as web

    calls = []
    monkeypatch.setattr(reactor, "listenTCP", lambda *args, **kwargs: calls.append(kwargs))
    monkeypatch.setattr(web, "ENABLE_XMLRPC", True)
    web.HLWebServices(object())
    assert calls == [{"interface": "127.0.0.1"}]


# ---------------------------------------------------------------------------
# Audit pass 1 (consecutive passes)
# ---------------------------------------------------------------------------


def close_later(client):
    """Like a real Twisted transport: loseConnection only starts closing;
    connectionLost comes later, so the protocol may still be holding
    buffered data when it decides to close."""

    def lose():
        client.transport.closed = True

    client.transport.loseConnection = lose


class TestNothingProcessedAfterClose:
    def test_logins_queued_behind_a_failed_one_are_ignored(self, irc_server):
        client = irc_server.hotline_client(host="10.4.4.4")
        close_later(client)
        # Two logins in one write: the second (correct) one must not run
        # on a connection already closing because of the first.
        sent = []
        real = client.conn.dataReceived
        client.conn.dataReceived = lambda data: sent.append(data)
        client.login("tester", "wrong")
        client.login("tester", "s3cret")
        client.conn.dataReceived = real
        client.conn.dataReceived(b"".join(sent))
        assert client.closed
        assert not client.user.isLoggedIn()

    def test_irc_lines_after_a_failed_login_are_ignored(self, irc_server):
        client = irc_server.irc_client()
        close_later(client)
        client.register("alice")
        client.send("PRIVMSG loginserv tester wrong", "PRIVMSG loginserv tester s3cret")
        assert not client.user.isLoggedIn()


class TestUploadFinish:
    def _upload(self, tmp_path, name, total=10):
        from shared.HLTransfer import HLUpload

        up = HLUpload(1, str(tmp_path / (name + ".hpf")), 1)
        up.total = total
        up.transferred = total
        return up

    def test_finishing_twice_never_renames_twice(self, tmp_path):
        (tmp_path / "readme.txt").write_text("original")
        up = self._upload(tmp_path, "readme.txt.hpf")
        up.finish()
        up.finish()
        assert (tmp_path / "readme.txt").read_text() == "original"
        assert (tmp_path / "readme.txt.hpf").exists()

    def test_existing_file_is_not_replaced(self, tmp_path):
        up = self._upload(tmp_path, "x")
        (tmp_path / "x").write_text("someone else's")
        up.finish()
        assert (tmp_path / "x").read_text() == "someone else's"

    def test_unknown_size_is_not_complete(self, tmp_path):
        up = self._upload(tmp_path, "empty", total=0)
        up.finish()
        assert not (tmp_path / "empty").exists()


def test_abandoned_transfers_close_their_file(irc_server, tmp_path):
    root = tmp_path / "files"
    root.mkdir(exist_ok=True)
    (root / "a.txt").write_text("a")
    for acct in irc_server.database.accounts:
        acct.fileRoot = str(root)
        acct.privs |= PRIV_DOWNLOAD_FILES
    client = irc_server.hotline_client()
    client.login("guest", "", "alice")
    client.send_packet(HTLC_HDR_FILE_GET, [(DATA_FILENAME, "a.txt")])
    (xfer,) = irc_server.server.fileserver.transfers.values()
    irc_server.clock.advance(31)
    assert irc_server.server.fileserver.transfers == {}
    assert xfer.file.closed


def test_refused_upload_writes_nothing_more(irc_server, tmp_path, monkeypatch):
    import shared.HLProtocol as proto
    from shared.HLProtocol import HTLC_HDR_FILE_PUT, PRIV_UPLOAD_ANYWHERE, PRIV_UPLOAD_FILES
    from server.HLFileServer import HLTransferConnection

    root = tmp_path / "files"
    root.mkdir(exist_ok=True)
    for acct in irc_server.database.accounts:
        acct.fileRoot = str(root)
        acct.privs |= PRIV_UPLOAD_FILES | PRIV_UPLOAD_ANYWHERE
    client = irc_server.hotline_client(host="10.0.0.1")
    client.login("guest", "", "alice")
    client.send_packet(HTLC_HDR_FILE_PUT, [(DATA_FILENAME, "big.bin")])
    (xfer,) = irc_server.server.fileserver.transfers.values()
    monkeypatch.setattr(proto, "MIN_FREE_SPACE_MB", 1 << 40)
    conn = HLTransferConnection()
    conn.factory = irc_server.server.fileserver
    conn.makeConnection(FakeXferTransport("10.0.0.1"))
    from shared.HLProtocol import HLCharConst

    header = struct.pack("!LHLLLLH", HLCharConst("FILP"), 1, 0, 0, 0, 0, 1)
    fork = struct.pack("!4L", HLCharConst("DATA"), 0, 0, 100000)
    conn.dataReceived(struct.pack("!4L", 0x48545846, xfer.id, 100000, 0))
    conn.dataReceived(header + fork + b"x" * 1000)
    if not xfer.file.closed:
        xfer.file.flush()
    assert os.path.getsize(root / "big.bin.hpf") == 0


def test_pre_login_irc_nick_is_cleaned(irc_server):
    client = irc_server.irc_client()
    client.send_raw(b"NICK ab\rcd" + b"x" * 100 + b"\r\nUSER a 0 * :a\r\n")
    assert client.user.nick == ("abcd" + "x" * 100)[:32]


# ---------------------------------------------------------------------------
# Audit pass 2: authorization
# ---------------------------------------------------------------------------


class TestPrivateChatPosting:
    def test_outsiders_cannot_post_into_a_private_chat(self, irc_server):
        member = irc_server.hotline_client()
        member.login("guest", "", "member")
        chat = irc_server.server.createChat()
        chat.addUser(member.user)
        member.transport.data = b""
        member._read = 0
        outsider = irc_server.hotline_client()
        outsider.login("guest", "", "outsider")
        outsider.send_packet(HTLC_HDR_CHAT, [(DATA_STRING, "spoofed"), (DATA_CHATID, struct.pack("!L", chat.id))])
        assert b"spoofed" not in member.transport.data
        assert errors(outsider) == ["You are not in this chat."]

    def test_members_can_post(self, irc_server):
        member = irc_server.hotline_client()
        member.login("guest", "", "member")
        chat = irc_server.server.createChat()
        chat.addUser(member.user)
        member.send_packet(HTLC_HDR_CHAT, [(DATA_STRING, "hello"), (DATA_CHATID, struct.pack("!L", chat.id))])
        assert b"hello" in member.transport.data


class TestAccountManagers:
    """A user who may manage accounts but isn't a full administrator."""

    @pytest.fixture
    def manager(self):
        from shared.HLProtocol import PRIV_CREATE_USERS, PRIV_DELETE_USERS, PRIV_MODIFY_USERS, PRIV_READ_USERS
        from tests.conftest import make_user

        privs = PRIV_CREATE_USERS | PRIV_DELETE_USERS | PRIV_MODIFY_USERS | PRIV_READ_USERS
        return make_user(uid=5, account=make_account(login="manager", privs=privs))

    def _packet(self, ptype, login, privs=None):
        from shared.HLProtocol import DATA_LOGIN, DATA_PRIVS, HLEncode, HLPacket

        packet = HLPacket(ptype, 1)
        packet.addString(DATA_LOGIN, HLEncode(login))
        if privs is not None:
            packet.addInt64(DATA_PRIVS, privs)
        return packet

    def test_cannot_create_more_powerful_account(self, fake_server, manager):
        from server.handlers.AcctHandler import AcctHandler
        from shared.HLProtocol import HTLC_HDR_ACCOUNT_CREATE, PRIV_BROADCAST

        with pytest.raises(HLException):
            AcctHandler().handleAccountCreate(fake_server, manager, self._packet(HTLC_HDR_ACCOUNT_CREATE, "evil", PRIV_BROADCAST))
        assert fake_server.database.loadAccount("evil") is None

    def test_cannot_modify_or_delete_the_admin(self, fake_server, manager):
        from server.handlers.AcctHandler import AcctHandler
        from shared.HLProtocol import HTLC_HDR_ACCOUNT_DELETE, HTLC_HDR_ACCOUNT_MODIFY

        fake_server.database.accounts.append(make_account(login="admin", privs=0xFFFFFFFFFFFFFFFF, password="hash"))
        with pytest.raises(HLException):
            AcctHandler().handleAccountModify(fake_server, manager, self._packet(HTLC_HDR_ACCOUNT_MODIFY, "admin", 0))
        with pytest.raises(HLException):
            AcctHandler().handleAccountDelete(fake_server, manager, self._packet(HTLC_HDR_ACCOUNT_DELETE, "admin"))
        assert fake_server.database.loadAccount("admin").password == "hash"

    def test_can_manage_lesser_accounts(self, fake_server, manager):
        from server.handlers.AcctHandler import AcctHandler
        from shared.HLProtocol import HTLC_HDR_ACCOUNT_CREATE, PRIV_READ_USERS

        AcctHandler().handleAccountCreate(fake_server, manager, self._packet(HTLC_HDR_ACCOUNT_CREATE, "helper", PRIV_READ_USERS))
        assert fake_server.database.loadAccount("helper").privs == PRIV_READ_USERS


def test_deleting_an_account_disconnects_its_sessions(irc_server):
    from server.handlers.AcctHandler import AcctHandler
    from shared.HLProtocol import DATA_LOGIN, HLEncode, HLPacket, HTLC_HDR_ACCOUNT_DELETE
    from tests.conftest import make_user

    victim = irc_server.hotline_client()
    victim.login("tester", "s3cret")
    assert victim.user.isLoggedIn()
    admin = make_user(uid=999, account=make_account(login="root", privs=0xFFFFFFFFFFFFFFFF))
    irc_server.server.sendPacket = lambda *args: None
    packet = HLPacket(HTLC_HDR_ACCOUNT_DELETE, 1)
    packet.addString(DATA_LOGIN, HLEncode("tester"))
    AcctHandler().handleAccountDelete(irc_server.server, admin, packet)
    assert victim.closed


def test_account_updates_match_logins_exactly(irc_server):
    from shared.HLProtocol import PRIV_BROADCAST

    client = irc_server.hotline_client()
    client.login("tester", "s3cret")
    other = make_account(login="TESTER", privs=PRIV_BROADCAST)
    irc_server.server.updateAccounts(other)
    assert not client.user.hasPriv(PRIV_BROADCAST)


# ---------------------------------------------------------------------------
# Audit pass 3: denial of service and data integrity
# ---------------------------------------------------------------------------


def _xfer_conn(irc_server, host):
    from server.HLFileServer import HLTransferConnection

    conn = HLTransferConnection()
    conn.factory = irc_server.server.fileserver
    transport = FakeXferTransport(host)
    transport.loseConnection = lambda: (setattr(transport, "closed", True), conn.connectionLost(None))
    conn.makeConnection(transport)
    return conn


class TestTransferPortLimits:
    def test_idle_connections_time_out(self, irc_server):
        conn = _xfer_conn(irc_server, "10.7.7.7")
        irc_server.clock.advance(31)
        assert conn.transport.closed

    def test_connections_per_address_are_limited(self, irc_server):
        conns = [_xfer_conn(irc_server, "10.7.7.8") for _ in range(11)]
        assert [c.transport.closed for c in conns] == [False] * 10 + [True]
        # Closing frees a slot.
        conns[0].closeConnection()
        assert not _xfer_conn(irc_server, "10.7.7.8").transport.closed

    def test_pending_transfers_per_user_are_limited(self, irc_server, tmp_path):
        root = tmp_path / "files"
        root.mkdir(exist_ok=True)
        (root / "a.txt").write_text("a")
        for acct in irc_server.database.accounts:
            acct.fileRoot = str(root)
            acct.privs |= PRIV_DOWNLOAD_FILES
        client = irc_server.hotline_client()
        client.login("guest", "", "alice")
        errors(client)
        for _ in range(21):
            client.send_packet(HTLC_HDR_FILE_GET, [(DATA_FILENAME, "a.txt")])
        assert len(irc_server.server.fileserver.transfers) == 20
        assert errors(client) == ["Too many file transfers at once, please wait for some to finish."]


class TestTextDatabaseIntegrity:
    @pytest.fixture
    def db(self, tmp_path, monkeypatch):
        from server.database.TextDatabase import TextDatabase

        db = TextDatabase()
        db.accountsFile = str(tmp_path / "accounts.txt")
        db.newsDir = str(tmp_path / "news")
        (tmp_path / "accounts.txt").write_text(
            "admin\t1\thash\tAdministrator\t0\t\t0\t0\t0000-00-00 00:00:00\n"
        )
        return db

    def test_failed_write_keeps_the_old_accounts(self, db, monkeypatch):
        import builtins

        real_open = builtins.open

        def failing_open(path, mode="r", *args, **kwargs):
            if str(path).endswith(".tmp"):
                raise OSError(28, "No space left on device")
            return real_open(path, mode, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", failing_open)
        with pytest.raises(OSError):
            db.updateAccountStats("admin", 0, 0, True)
        monkeypatch.setattr(builtins, "open", real_open)
        assert db.loadAccount("admin") is not None

    def test_news_posts_are_never_overwritten(self, db):
        from shared.HLTypes import HLNewsPost

        os.makedirs(db.newsDir)
        # Unsorted listings must not make a new post reuse a number.
        for n in (1, 2, 10):
            with open(os.path.join(db.newsDir, "%d.txt" % n), "w") as fp:
                fp.write("%d\t2026-01-01\tlogin\tnick\npost %d" % (n, n))
        db.saveNewsPost(HLNewsPost("nick", "login", "new post"))
        assert open(os.path.join(db.newsDir, "11.txt")).read().endswith("new post")
        for n in (1, 2, 10):
            assert open(os.path.join(db.newsDir, "%d.txt" % n)).read().endswith("post %d" % n)


def test_chat_is_not_logged_when_disk_is_low(irc_server, tmp_path, monkeypatch):
    import server.handlers.ChatHandler as chat
    import shared.HLProtocol as proto

    (tmp_path / "chatlogs").mkdir()
    monkeypatch.setattr(chat, "LOG_DIR", str(tmp_path / "chatlogs"))
    monkeypatch.setattr(proto, "MIN_FREE_SPACE_MB", 1 << 40)
    client = irc_server.hotline_client()
    client.login("guest", "", "alice")
    client.send_packet(HTLC_HDR_CHAT, [(DATA_STRING, "hello")])
    assert os.listdir(tmp_path / "chatlogs") == []


def test_find_is_bounded(irc_server, tmp_path, monkeypatch):
    import server.handlers.commands.find as find

    root = tmp_path / "files"
    root.mkdir(exist_ok=True)
    for i in range(50):
        (root / ("match%d" % i)).write_text("")
    monkeypatch.setattr(find, "FIND_MAX_MATCHES", 10)
    for acct in irc_server.database.accounts:
        acct.fileRoot = str(root)
    client = irc_server.hotline_client()
    client.login("guest", "", "alice")
    client.send_packet(HTLC_HDR_CHAT, [(DATA_STRING, "/find match")])
    out = client.transport.data
    assert out.count(b"- /match") <= 10
    assert b"search stopped" in out


# ---------------------------------------------------------------------------
# Audit pass 4: TLS
# ---------------------------------------------------------------------------


def test_tls_renegotiation_is_disabled(tmp_path):
    from OpenSSL import SSL

    from server.HLTLS import buildServerContext
    from tests.test_tls import write_cert

    cert, key = write_cert(tmp_path, "server")
    context = buildServerContext(str(cert), str(key))
    options = context.set_options(0)  # adds nothing, returns the current options
    assert options & getattr(SSL, "OP_NO_RENEGOTIATION", 0x40000000)
    assert options & SSL.OP_NO_COMPRESSION


# ---------------------------------------------------------------------------
# Audit pass 5: control characters in file names
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["a\nb", "a\rb", "a\tb", "a\x1bb"])
def test_file_names_with_control_characters_are_refused(tmp_path, name):
    from server.handlers.FileHandler import buildPath

    with pytest.raises(HLException):
        buildPath(str(tmp_path), [], name)
    with pytest.raises(HLException):
        buildPath(str(tmp_path), [name], "x")


# ---------------------------------------------------------------------------
# Audit pass 6: hidden files and the default admin password
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("dirs, name", [([], ".env"), ([".git"], "config"), (["sub"], ".hidden")])
def test_hidden_files_are_unreachable(tmp_path, dirs, name):
    from server.handlers.FileHandler import buildPath

    with pytest.raises(HLException):
        buildPath(str(tmp_path), dirs, name)


def test_hidden_files_reachable_when_shown(tmp_path, monkeypatch):
    import server.handlers.FileHandler as fh

    monkeypatch.setattr(fh, "SHOW_DOTFILES", True)
    assert fh.buildPath(str(tmp_path), [], ".env").endswith(".env")


def test_find_skips_hidden_files(irc_server, tmp_path):
    root = tmp_path / "files"
    root.mkdir(exist_ok=True)
    (root / ".secret-match").write_text("")
    (root / ".git").mkdir()
    (root / ".git" / "match").write_text("")
    (root / "visible-match").write_text("")
    for acct in irc_server.database.accounts:
        acct.fileRoot = str(root)
    client = irc_server.hotline_client()
    client.login("guest", "", "alice")
    client.send_packet(HTLC_HDR_CHAT, [(DATA_STRING, "/find match")])
    assert b"visible-match" in client.transport.data
    assert b"secret" not in client.transport.data
    assert b".git" not in client.transport.data


def test_default_admin_password_is_replaced(irc_server):
    from hashlib import md5

    admin = make_account(login="admin", privs=0xFFFFFFFFFFFFFFFF, password=md5(b"adminpass").hexdigest())
    irc_server.database.accounts.append(admin)
    from shared.HLPassword import verifyPassword

    password = irc_server.server.secureDefaultAdmin()
    assert password
    assert verifyPassword(admin.password, password)
    assert not verifyPassword(admin.password, "adminpass")
    assert irc_server.server.secureDefaultAdmin() is None


def test_changed_admin_password_is_left_alone(irc_server):
    admin = make_account(login="admin", privs=0xFFFFFFFFFFFFFFFF, password="somethingelse")
    irc_server.database.accounts.append(admin)
    assert irc_server.server.secureDefaultAdmin() is None
    assert admin.password == "somethingelse"


# ---------------------------------------------------------------------------
# Audit pass 7: concurrent uploads of the same name
# ---------------------------------------------------------------------------


def test_same_name_cannot_be_uploaded_twice_at_once(irc_server, tmp_path):
    from shared.HLProtocol import HTLC_HDR_FILE_PUT, PRIV_UPLOAD_ANYWHERE, PRIV_UPLOAD_FILES

    root = tmp_path / "files"
    root.mkdir(exist_ok=True)
    for acct in irc_server.database.accounts:
        acct.fileRoot = str(root)
        acct.privs |= PRIV_UPLOAD_FILES | PRIV_UPLOAD_ANYWHERE
    first = irc_server.hotline_client()
    first.login("guest", "", "alice")
    first.send_packet(HTLC_HDR_FILE_PUT, [(DATA_FILENAME, "shared.bin")])
    second = irc_server.hotline_client()
    second.login("tester", "s3cret")
    errors(second)
    second.send_packet(HTLC_HDR_FILE_PUT, [(DATA_FILENAME, "shared.bin")])
    assert errors(second) == ["This file is already being uploaded."]
    assert len(irc_server.server.fileserver.transfers) == 1


# ---------------------------------------------------------------------------
# Audit pass 11: account names in IRC WHO
# ---------------------------------------------------------------------------


def test_who_hides_other_account_names(irc_server):
    from tests.test_irc import logged_in_irc_client

    watcher = logged_in_irc_client(irc_server)
    hl = irc_server.hotline_client()
    hl.login("tester", "s3cret", "eve")
    watcher.take()
    watcher.send("WHO #public")
    lines = [line for line in watcher.take() if " 352 " in line]
    assert lines
    assert not any("Tester" in line for line in lines)


# ---------------------------------------------------------------------------
# Audit pass 12: user IDs must stay 16-bit
# ---------------------------------------------------------------------------


def test_user_ids_wrap_within_16_bits(irc_server):
    from shared.HLProtocol import HTLC_HDR_USER_LIST

    first = irc_server.hotline_client()
    first.login("guest", "", "first")
    # As if 65535 connections had come and gone since the server started.
    irc_server.server.lastUID = 0xFFFF
    late = irc_server.hotline_client()
    late.login("guest", "", "late")
    assert 0 < late.uid <= 0xFFFF
    assert late.uid != first.uid
    # The user list (which packs uids as 16 bits) still works for everyone.
    first.send_packet(HTLC_HDR_USER_LIST, [])
    assert not first.closed
    assert b"late" in first.transport.data


# ---------------------------------------------------------------------------
# Audit pass 13: password storage
# ---------------------------------------------------------------------------


class TestPasswordHashing:
    def test_hashes_are_salted_stretched_and_fit_the_column(self):
        from shared.HLPassword import hashPassword, verifyPassword

        a, b = hashPassword("secret"), hashPassword("secret")
        assert a != b  # salted
        assert a.startswith("$p1$") and len(a) <= 64
        assert verifyPassword(a, "secret") and verifyPassword(a, b"secret")
        assert not verifyPassword(a, "Secret")
        assert verifyPassword(hashPassword(""), "")

    def test_legacy_md5_still_works(self):
        from hashlib import md5

        from shared.HLPassword import needsUpgrade, verifyPassword

        legacy = md5(b"secret").hexdigest()
        assert verifyPassword(legacy, "secret")
        assert not verifyPassword(legacy, "wrong")
        assert needsUpgrade(legacy)

    @pytest.mark.parametrize("stored", ["", "garbage", "$p1$", "$p1$!!$!!"])
    def test_malformed_hashes_never_match(self, stored):
        from shared.HLPassword import verifyPassword

        assert not verifyPassword(stored, "")
        assert not verifyPassword(stored, "garbage")

    def test_legacy_hash_is_upgraded_on_login(self, irc_server):
        from shared.HLPassword import needsUpgrade, verifyPassword

        saved = []
        real_save = irc_server.database.saveAccount
        irc_server.database.saveAccount = lambda acct: (saved.append((acct.password, acct.fileRoot)), real_save(acct))[1]
        client = irc_server.hotline_client()
        client.login("tester", "s3cret")
        assert client.user.isLoggedIn()
        ((password, file_root),) = saved
        assert not needsUpgrade(password)
        assert verifyPassword(password, "s3cret")
        # The default file root filled in for the session isn't saved.
        assert file_root == ""
        # And the upgraded hash works for the next login.
        again = irc_server.hotline_client()
        again.login("tester", "s3cret")
        assert again.user.isLoggedIn()

    def test_new_passwords_use_the_new_format(self, fake_server, admin_user):
        from server.handlers.AcctHandler import AcctHandler
        from shared.HLPassword import needsUpgrade, verifyPassword
        from shared.HLProtocol import DATA_LOGIN, DATA_PASSWORD, HLEncode, HLPacket, HTLC_HDR_ACCOUNT_CREATE

        packet = HLPacket(HTLC_HDR_ACCOUNT_CREATE, 1)
        packet.addString(DATA_LOGIN, HLEncode("newbie"))
        packet.addString(DATA_PASSWORD, HLEncode("pw123"))
        AcctHandler().handleAccountCreate(fake_server, admin_user, packet)
        stored = fake_server.database.loadAccount("newbie").password
        assert not needsUpgrade(stored) and verifyPassword(stored, "pw123")


# ---------------------------------------------------------------------------
# Audit pass 14: traffic before login
# ---------------------------------------------------------------------------


def test_too_many_packets_before_login_closes_the_connection(irc_server, capsys):
    from shared.HLProtocol import HTLC_HDR_USER_LIST

    client = irc_server.hotline_client()
    for _ in range(60):
        client.send_packet(HTLC_HDR_USER_LIST, [])
    assert client.closed
    # And nothing was printed for them.
    assert "before login" not in capsys.readouterr().out


def test_normal_irc_registration_is_well_under_the_limit(irc_server):
    client = irc_server.irc_client()
    client.send("CAP LS 302", "NICK alice", "USER alice 0 * :Alice", "CAP END", "PING :x", "MODE alice +i")
    client.send("PRIVMSG loginserv guest")
    assert client.user.isLoggedIn()
    assert not client.closed


# ---------------------------------------------------------------------------
# Audit pass 15: rate limits on expensive actions
# ---------------------------------------------------------------------------


def test_scripts_are_rate_limited(irc_server, exec_dir):
    client = irc_server.hotline_client()
    client.login("guest", "", "alice")
    calls = []
    import shared.HLUtils as utils

    real = utils.shell_exec
    import server.handlers.ChatHandler as chat

    chat.shell_exec = lambda *args: calls.append(args) or "out"
    try:
        client.send_packet(HTLC_HDR_CHAT, [(DATA_STRING, "\r".join(["/echoargs"] * 20))])
    finally:
        chat.shell_exec = real
    assert len(calls) == 5
    assert b"Too many commands" in client.transport.data


def test_logins_per_address_are_rate_limited(irc_server):
    for _ in range(20):
        client = irc_server.hotline_client(host="10.8.8.8")
        client.login("guest", "", "alice")
        assert client.user.isLoggedIn()
        client.conn.closeConnection()
    client = irc_server.hotline_client(host="10.8.8.8")
    client.login("guest", "", "alice")
    assert errors(client) == ["Too many logins from your address, please try again in a minute."]
    # Other addresses are unaffected, and the limit passes.
    other = irc_server.hotline_client(host="10.8.8.9")
    other.login("guest", "", "bob")
    assert other.user.isLoggedIn()


# ---------------------------------------------------------------------------
# Audit pass 16: broadcast amplification
# ---------------------------------------------------------------------------


def _chat_lines_received(client):
    return client.transport.data.count(b"spam")


def test_one_message_cannot_become_thousands_of_broadcasts(irc_server):
    watcher = irc_server.hotline_client()
    watcher.login("guest", "", "watcher")
    sender = irc_server.hotline_client()
    sender.login("guest", "", "sender")
    sender.send_packet(HTLC_HDR_CHAT, [(DATA_STRING, "spam\r" * 5000)])
    assert _chat_lines_received(watcher) == 20


def test_chat_lines_per_user_are_rate_limited(irc_server):
    watcher = irc_server.hotline_client()
    watcher.login("guest", "", "watcher")
    sender = irc_server.hotline_client()
    sender.login("guest", "", "sender")
    for _ in range(10):
        sender.send_packet(HTLC_HDR_CHAT, [(DATA_STRING, "spam\rspam\rspam\rspam\rspam")])
    assert _chat_lines_received(watcher) == 30


def test_icon_changes_are_rate_limited(irc_server):
    from shared.HLProtocol import DATA_GIFICON, HTLC_HDR_ICON_SET

    client = irc_server.hotline_client()
    client.login("guest", "", "alice")
    errors(client)
    for _ in range(6):
        client.send_packet(HTLC_HDR_ICON_SET, [(DATA_GIFICON, b"GIF89a")])
    assert errors(client) == ["Please wait a minute before changing your icon again."]


# ---------------------------------------------------------------------------
# Audit pass 17: clients that don't read
# ---------------------------------------------------------------------------


def test_client_that_stops_reading_is_disconnected(irc_server):
    client = irc_server.hotline_client()
    client.login("guest", "", "alice")
    aborted = []
    client.transport.abortConnection = lambda: aborted.append(True)
    # The transport's send buffer is full; Twisted reports it again on
    # every write while it stays full.
    client.conn.pauseProducing()
    for _ in range(100):
        client.conn.pauseProducing()
        client.conn.send(b"x" * 64 * 1024)
        if aborted:
            break
    assert aborted
    assert len(client.transport.data) < 3 * 1024 * 1024


def test_reading_client_is_resumed(irc_server):
    client = irc_server.hotline_client()
    client.login("guest", "", "alice")
    client.conn.pauseProducing()
    client.conn.send(b"x" * 1000)
    client.conn.resumeProducing()
    client.conn.send(b"y" * (3 * 1024 * 1024))
    assert not client.closed


# ---------------------------------------------------------------------------
# Audit pass 18: addresses that stand for many clients
# ---------------------------------------------------------------------------


def test_default_gateway_is_read_from_the_routing_table(tmp_path):
    from shared.HLProtocol import defaultGateway

    routes = tmp_path / "route"
    routes.write_text(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
        "eth0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\n"
        "eth0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\n"
    )
    assert defaultGateway(str(routes)) == "172.17.0.1"
    assert defaultGateway(str(tmp_path / "missing")) is None


class TestSharedAddresses:
    @pytest.fixture
    def gateway(self, irc_server):
        irc_server.server.shared = {"172.17.0.1"}
        return "172.17.0.1"

    def test_failed_logins_do_not_ban_everyone_behind_it(self, irc_server, gateway):
        for _ in range(6):
            client = irc_server.hotline_client(host=gateway)
            client.login("tester", "wrong")
        client = irc_server.hotline_client(host=gateway)
        client.login("tester", "s3cret")
        assert client.user.isLoggedIn()

    def test_connection_limit_does_not_lock_everyone_out(self, irc_server, gateway):
        clients = [irc_server.irc_client(host=gateway) for _ in range(15)]
        assert not any(c.closed for c in clients)

    def test_kick_ban_is_not_applied(self, irc_server, gateway):
        irc_server.server.addTempBan(gateway, "kicked")
        assert irc_server.server.checkForBan(gateway) is None

    def test_ordinary_addresses_are_still_limited(self, irc_server, gateway):
        clients = [irc_server.irc_client(host="10.5.5.5") for _ in range(11)]
        assert clients[-1].closed


# ---------------------------------------------------------------------------
# Audit pass 19: icon lists and private chat creation
# ---------------------------------------------------------------------------


def test_icon_list_requests_are_rate_limited(irc_server):
    from shared.HLProtocol import HTLC_HDR_ICON_LIST

    client = irc_server.hotline_client()
    client.login("guest", "", "alice")
    errors(client)
    for _ in range(6):
        client.send_packet(HTLC_HDR_ICON_LIST, [])
    assert errors(client) == ["Please wait a few seconds before asking for the icons again."]


def test_private_chat_creation_is_rate_limited(irc_server):
    from shared.HLProtocol import HTLC_HDR_CHAT_CREATE, PRIV_CREATE_CHATS

    guest = next(a for a in irc_server.database.accounts if a.login == "guest")
    guest.privs |= PRIV_CREATE_CHATS
    client = irc_server.hotline_client()
    client.login("guest", "", "alice")
    errors(client)
    for _ in range(11):
        client.send_packet(HTLC_HDR_CHAT_CREATE, [])
    assert len(irc_server.server.chats) == 10
    assert errors(client) == ["Please wait a minute before creating more private chats."]
