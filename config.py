from __future__ import absolute_import
import os
################################################################################
# database configuration
################################################################################

# DB_TYPE actually specifies the prefix of the class that will be used
# for all database operations (accounts, news, login, banlist, etc)
# i.e. MySQL would mean use the MySQLDatabase class in database/MySQLDatabase.py
# available database types:
#    * MySQL
#    * Text
DB_TYPE = "Text"

# used when DB_TYPE is MySQL
DB_HOST = "localhost"
DB_USER = "root"
DB_PASS = ""
DB_NAME = "phxd"

# used when DB_TYPE is Text
DB_FILE_BASEPATH = "textdb"
DB_FILE_NEWSDIR = os.path.join(DB_FILE_BASEPATH, "db_news")
DB_FILE_ACCOUNTS = os.path.join(DB_FILE_BASEPATH, "db_accounts.txt")
DB_FILE_LOG = os.path.join(DB_FILE_BASEPATH, "db_log.txt")
DB_FILE_BANLIST = os.path.join(DB_FILE_BASEPATH, "db_banlist.txt")

################################################################################
# logging configuration
################################################################################

ENABLE_FILE_LOG = True
LOG_FILE = os.path.join(DB_FILE_BASEPATH, "phxd.log")
LOG_MAX_SIZE_MBYTES = 10
MAX_LOG_FILES = 5
# Minimum level of the messages written to stdout ("docker logs") and to
# LOG_FILE: DEBUG, INFO, WARNING, ERROR or CRITICAL. DEBUG includes hex
# dumps of every packet, so only use it for troubleshooting.
LOG_LEVEL = "INFO"
# At most this many log lines per minute (errors and security warnings
# are always kept); beyond it, lines are dropped and counted, so a flood
# of connections can't grow the logs (and fill the disk) without limit.
# 0 = unlimited.
LOG_LINES_PER_MINUTE = 300

################################################################################
# server configuration
################################################################################

SERVER_PORT = 5500
SERVER_NAME = "phxd server"
SERVER_DESCRIPTION = "Yet another phxd server instance"
IDLE_TIME = 10 * 60
# Dead connection detection. Clients whose network drops without closing
# the connection would otherwise stay listed for 15+ minutes (or forever
# while idle). TCP keepalive probes a connection after TCP_KEEPALIVE_IDLE
# seconds of silence, every TCP_KEEPALIVE_INTERVAL seconds, and drops it
# after TCP_KEEPALIVE_COUNT unanswered probes; TCP_USER_TIMEOUT drops a
# connection whose sent data stays unacknowledged that many seconds.
# Set TCP_KEEPALIVE_IDLE or TCP_USER_TIMEOUT to 0 to disable them.
TCP_KEEPALIVE_IDLE = 60
TCP_KEEPALIVE_INTERVAL = 15
TCP_KEEPALIVE_COUNT = 4
TCP_USER_TIMEOUT = 90
BAN_TIME = 15 * 60
# Abuse limits.
#  - LOGIN_TIMEOUT: seconds a connection may stay open without logging in.
#  - MAX_CONNECTIONS_PER_IP: simultaneous connections allowed from one
#    address (0 = unlimited).
#  - MAX_LOGIN_FAILURES: failed logins from one address within
#    LOGIN_FAILURE_WINDOW seconds before it is banned for BAN_TIME
#    (0 = never ban).
#  - MAX_PACKET_SIZE: largest Hotline transaction accepted, in bytes.
#  - MAX_IRC_LINE: longest IRC line accepted, in bytes.
LOGIN_TIMEOUT = 60
MAX_CONNECTIONS_PER_IP = 10
# Connections accepted at once in total, on the main and on the transfer
# port each, whatever their address (0 = unlimited).
MAX_CONNECTIONS_TOTAL = 1000
# New connections accepted per address per minute (0 = unlimited).
MAX_CONNECTS_PER_MINUTE = 60
MAX_LOGIN_FAILURES = 5
# Login attempts (successful or not) accepted per address per minute, and
# server-side scripts or /find searches per user per 10 seconds: each
# costs real work on the server's single thread (0 = unlimited).
MAX_LOGINS_PER_MINUTE = 20
# Addresses that stand for many clients at once (a proxy, or Docker's
# gateway when it forwards IPv6 connections to an IPv4-only container):
# per-address limits and bans are not applied to them, since they would
# hit every client behind them. "auto" adds this host's default gateway.
SHARED_ADDRESSES = ["auto"]
MAX_COMMANDS_PER_10S = 5
LOGIN_FAILURE_WINDOW = 5 * 60
MAX_PACKET_SIZE = 256 * 1024
MAX_IRC_LINE = 8192

# Path (relative to the server working directory or absolute) to a plain-
# text file containing the connection agreement. The classic 1.9 client
# and most modern clients block Chat/Files/News until they receive this
# push from the server. If the file is missing or empty the server still
# pushes an empty agreement so the client unblocks.
SERVER_AGREEMENT_PATH = "support/agreement.txt"

################################################################################
# tracker client options
################################################################################

# TRACKER_LIST example:
#TRACKER_LIST=[("tracker.hostname.tld", 5499),
#              ("127.0.0.1", 5499)]
TRACKER_LIST=[]
TRACKER_REFRESH_PERIOD=60


################################################################################
# chat options
################################################################################

CHAT_FORMAT = "\r%13.13s:  %s"
EMOTE_FORMAT = "\r ### %s %s"
MAX_NICK_LEN = 32
MAX_CHAT_LEN = 4096
# Chat lines are broadcast to everyone, one packet per line per user: at
# most MAX_CHAT_LINES lines per message and MAX_CHAT_LINES_PER_10S lines
# per user per 10 seconds are sent on (0 = unlimited).
MAX_CHAT_LINES = 20
MAX_CHAT_LINES_PER_10S = 30
LOG_CHAT = True
LOG_DIR = "chatlogs"

################################################################################
# files options
################################################################################

FILE_ROOT = "files"
SHOW_DOTFILES = False
# Symbolic links inside FILE_ROOT that lead outside it are not followed
# unless this is True (only enable it if you trust every link in there).
ALLOW_LINKS_OUTSIDE_FILE_ROOT = False

################################################################################
# transfer options
##########################################################

XFER_START_TIMEOUT = 30
# Transfers a user may have waiting or in progress at once.
MAX_TRANSFERS_PER_USER = 20
# Uploads are refused if they would leave less than this much free space
# (in megabytes) on the disk holding FILE_ROOT, so uploaders can't fill
# the server's disk.
MIN_FREE_SPACE_MB = 1024

################################################################################
# GIF icon options
################################################################################

ENABLE_GIF_ICONS = True
MAX_GIF_SIZE = 32768

################################################################################
# XML-RPC options
################################################################################

ENABLE_XMLRPC = False
XMLRPC_PORT = 5800
# XML-RPC has no authentication and reveals users' IP addresses: it only
# listens on this interface ("0.0.0.0" for all of them; firewall it then).
XMLRPC_INTERFACE = "127.0.0.1"

################################################################################
# IRC options
################################################################################

IRC_SERVER_NAME = "phxd"
# Seconds to wait after an IRC client connects for it to log in (server
# password, /msg NickServ IDENTIFY or /msg loginserv) before logging it in
# automatically as guest. Requires a "guest" account. 0 disables auto-guest.
IRC_GUEST_LOGIN_DELAY = 5
# TLS. TLS_CERT / TLS_KEY are the PEM certificate chain and private key
# used by all TLS ports, e.g. Let's Encrypt's fullchain.pem and privkey.pem;
# the files are reloaded automatically when they change (renewals).
#  - HOTLINE_TLS_PORT: Hotline over TLS (5600 by convention, as used by
#    Mobius and the mierau/hotline client), with TLS file transfers on the
#    port after it. Advertised to trackers.
#  - IRC_TLS_PORT: IRC over TLS (6697 is the standard IRC TLS port).
# 0 disables a port. Connections on TLS ports are otherwise identical to
# SERVER_PORT ones.
TLS_CERT = ""
TLS_KEY = ""
HOTLINE_TLS_PORT = 0
IRC_TLS_PORT = 0


################################################################################
# Server linking options
################################################################################

ENABLE_SERVER_LINKING = False
LINK_PORT = SERVER_PORT + 3
# Linked servers are trusted completely and there is no authentication,
# so only these addresses may connect to LINK_PORT.
LINK_ALLOWED_HOSTS = ["127.0.0.1", "::1"]


################################################################################
# YAML overrides
################################################################################

# Any setting above can be overridden from a YAML file, read at startup:
# $PHXD_CONFIG if set, otherwise phxd.yaml next to this file. Settings are
# written in lower case, e.g.:
#
#   server_name: "My Hotline server"
#   tracker_list:
#     - tracker.preterhuman.net:5499
#   log_level: INFO
#
# In Docker, mount the file into the container (see README.md) so the
# configuration can change with a restart instead of an image rebuild.
from shared.HLConfig import loadOverrides as _loadOverrides
CONFIG_OVERRIDDEN = _loadOverrides( globals() , os.path.dirname( os.path.abspath( __file__ ) ) )

# The Docker entrypoint passes readable copies of the TLS certificate and
# key (see docker/run-phxd.sh); these take precedence when set.
TLS_CERT = os.environ.get( "PHXD_TLS_CERT" ) or TLS_CERT
TLS_KEY = os.environ.get( "PHXD_TLS_KEY" ) or TLS_KEY
