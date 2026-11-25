from __future__ import absolute_import
from __future__ import print_function
from twisted.internet.protocol import Factory , Protocol
from twisted.internet import task
from twisted.internet import reactor
from shared.HLProtocol import *
from shared.HLTypes import *
from server.HLDatabase import getDatabase
from server.HLFileServer import *
from server.HLWebServices import *
from server.HLDatabaseLogger import *
from server.HLServerLinkage import *
from server.HLTracker import HLTrackerClient
from server.HLTLS import GracefulCloseMixin
import os
import sys
import socket
from struct import error as StructError
#from twisted.logger import globalLogBeginner, textFileLogObserver
#globalLogBeginner.beginLoggingTo([textFileLogObserver(sys.stdout)])

from config import *
import time , logging
from logging.handlers import RotatingFileHandler

class LogRateLimiter( logging.Filter ):
    """ Lets at most ``perMinute`` log records through per minute, plus
    every error and security warning; drops the rest and reports how many
    were dropped once the minute is over. """

    def __init__( self , logger , perMinute , clock = time.time ):
        logging.Filter.__init__( self )
        self.logger = logger
        self.perMinute = perMinute
        self.clock = clock
        self.windowStart = clock()
        self.count = 0
        self.suppressed = 0
        self.reporting = False

    def filter( self , record ):
        if self.reporting or ( self.perMinute <= 0 ):
            return True
        if record.levelno < getattr( logging , LOG_LEVEL , logging.INFO ):
            # Below the configured level: the handlers drop it anyway, it
            # mustn't use up the budget.
            return True
        if ( record.levelno >= logging.ERROR ) or str( record.msg ).startswith( "SECURITY" ):
            return True
        now = self.clock()
        if now - self.windowStart >= 60:
            suppressed = self.suppressed
            self.windowStart = now
            self.count = 0
            self.suppressed = 0
            if suppressed:
                self.reporting = True
                try:
                    self.logger.warning( "%d log lines suppressed in the last minute (more than %d per minute)" , suppressed , self.perMinute )
                finally:
                    self.reporting = False
        if self.count >= self.perMinute:
            self.suppressed += 1
            return False
        self.count += 1
        return True

def findSocket( transport , maxDepth = 5 ):
    """ Returns the OS socket under a Twisted transport, unwrapping TLS
    (TLSMemoryBIOProtocol / BufferingTLSTransport) layers, or None. """
    for _ in range( maxDepth ):
        if transport is None:
            return None
        sock = getattr( transport , "socket" , None )
        if isinstance( sock , socket.socket ):
            return sock
        nextTransport = getattr( transport , "transport" , None )
        if nextTransport is None:
            nextTransport = getattr( getattr( transport , "_protocol" , None ) , "transport" , None )
        transport = nextTransport
    return None

def enableDeadPeerDetection( sock , idle = None , interval = None , count = None , userTimeout = None ):
    """ Enables TCP keepalive and the TCP user timeout on ``sock`` so
    connections whose peer vanished (network drop, sleep, NAT timeout)
    are closed within minutes instead of lingering. Options the platform
    lacks are skipped. Returns the options that were set. """
    idle = TCP_KEEPALIVE_IDLE if idle is None else idle
    interval = TCP_KEEPALIVE_INTERVAL if interval is None else interval
    count = TCP_KEEPALIVE_COUNT if count is None else count
    userTimeout = TCP_USER_TIMEOUT if userTimeout is None else userTimeout
    applied = {}
    if idle > 0:
        sock.setsockopt( socket.SOL_SOCKET , socket.SO_KEEPALIVE , 1 )
        applied["SO_KEEPALIVE"] = 1
        for name , value in ( ( "TCP_KEEPIDLE" , idle ) , ( "TCP_KEEPINTVL" , interval ) , ( "TCP_KEEPCNT" , count ) ):
            option = getattr( socket , name , None )
            if option is not None and value > 0:
                sock.setsockopt( socket.IPPROTO_TCP , option , int( value ) )
                applied[name] = int( value )
    option = getattr( socket , "TCP_USER_TIMEOUT" , None )
    if option is not None and userTimeout > 0:
        sock.setsockopt( socket.IPPROTO_TCP , option , int( userTimeout * 1000 ) )
        applied["TCP_USER_TIMEOUT"] = int( userTimeout * 1000 )
    return applied

class HLConnection( GracefulCloseMixin , Protocol ):
    """ Protocol subclass to handle parsing and dispatching of raw hotline data. """
    
    def __init__( self , factory , connID ):
        self.factory = factory
        self.connID = connID
    
    def connectionMade( self ):
        """ Called when a connection is accepted. """
        self.gotMagic = False
        self.isIRC = False
        self.packet = HLPacket()
        self.buffer = b''
        self.capReplied = False
        self.preLoginPackets = 0
        # Backpressure: the transport pauses us (as a streaming producer)
        # when its send buffer is full; a client that stops reading is
        # disconnected once MAX_PENDING_OUTPUT more bytes pile up, instead
        # of the server holding ever more unread output in memory.
        self.outputPaused = False
        self.pausedBytes = 0
        try:
            self.transport.registerProducer( self , True )
        except Exception:
            pass
        self.guestTimer = None
        self.idleTimer = reactor.callLater( IDLE_TIME , self.idleCheck )
        # Connections that never log in are dropped after LOGIN_TIMEOUT.
        self.loginTimer = None
        if LOGIN_TIMEOUT > 0:
            self.loginTimer = reactor.callLater( LOGIN_TIMEOUT , self.loginTimeoutCheck )
        try:
            sock = findSocket( self.transport )
            if sock is not None:
                enableDeadPeerDetection( sock )
        except OSError as e:
            self.factory.log.warning( "Could not enable dead connection detection: %s" , e )
        user = self.factory.getUser( self.connID )
        if ( MAX_CONNECTIONS_TOTAL > 0 ) and ( len( self.factory.clients ) > MAX_CONNECTIONS_TOTAL ):
            self.quiet = True
            self.factory.logFull()
            self.closeConnection()
            return
        if ( user is not None ) and not self.factory.allowConnect( user.ip ):
            # Connecting too often: drop it without logging every attempt.
            self.quiet = True
            self.closeConnection()
            return
        try:
            peer = self.transport.getPeer()
            self.factory.log.info( "Client connected: %s:%s (connID=%d)" , peer.host , peer.port , self.connID )
        except Exception:
            pass
        if ( user is not None ) and self.factory.tooManyConnections( user.ip ):
            self.factory.log.warning( "Too many connections from %s, refusing connID=%d" , user.ip , self.connID )
            self.closeConnection()

    def connectionLost( self , reason ):
        """ Called when the connection is lost. """
        self.connectionClosed()
        if ( self.idleTimer != None ) and self.idleTimer.active():
            self.idleTimer.cancel()
        if ( self.guestTimer != None ) and self.guestTimer.active():
            self.guestTimer.cancel()
        if ( self.loginTimer != None ) and self.loginTimer.active():
            self.loginTimer.cancel()
        try:
            if not getattr( self , "quiet" , False ):
                self.factory.log.info( "Client disconnected (connID=%d): %s" , self.connID , reason.getErrorMessage() if hasattr( reason , 'getErrorMessage' ) else reason )
        except Exception:
            pass
        self.factory.removeConnection( self.connID )

    def dataReceived( self , data ):
        """ Called when the socket receives data. """
        try:
            self.factory.log.debug(
                "dataReceived connID=%d gotMagic=%s isIRC=%s len=%d hex=%s" ,
                self.connID , self.gotMagic , self.isIRC , len( data ) ,
                data.hex() if isinstance( data , (bytes , bytearray) ) else '<not bytes>'
            )
        except Exception:
            pass
        if self.closing:
            return
        self.buffer += data
        try:
            self.parseBuffer()
        except StructError:
            # struct.error: a malformed Hotline packet. Not worth a
            # traceback in the log (anyone can send these).
            self.factory.log.info( "Malformed packet from connID=%d, closing" , self.connID )
            self.closeConnection()
        except Exception:
            # Don't let an exception inside parseBuffer disappear into
            # Twisted — log it explicitly so it shows in docker logs.
            self.factory.log.exception( "Unhandled exception in parseBuffer (connID=%d)" , self.connID )
            self.closeConnection()
    
    def parseBuffer( self ):
        """ Parses the current buffer until the buffer is empty or until no more packets can be parsed. """
        if self.gotMagic:
            done = False
            while not done:
                if self.closing:
                    # E.g. a failed login: don't process anything queued
                    # behind it.
                    self.buffer = b''
                    return
                if self.isIRC:
                    # One complete line at a time; a line (or a partial
                    # one) longer than MAX_IRC_LINE closes the connection
                    # rather than buffering without limit.
                    end = self.buffer.find( b"\n" )
                    if end < 0:
                        if len( self.buffer ) > MAX_IRC_LINE:
                            self.factory.log.warning( "IRC line too long from connID=%d, closing" , self.connID )
                            self.buffer = b''
                            self.closeConnection()
                        return
                    line = self.buffer[:end].replace( b"\r" , b"" )
                    self.buffer = self.buffer[end+1:]
                    if len( line ) > MAX_IRC_LINE:
                        self.factory.log.warning( "IRC line too long from connID=%d, closing" , self.connID )
                        self.buffer = b''
                        self.closeConnection()
                        return
                    if not line:
                        continue
                    self.packet.isIRC = self.isIRC
                    self.packet.connID = self.connID
                    self.packet.server = self.factory
                    try:
                        self.packet.parse( line )
                    except ( IndexError , ValueError ):
                        # Malformed line (e.g. "NICK" with no nick):
                        # ignore it rather than drop the connection.
                        self.packet = HLPacket()
                        continue
                    self.handlePacket()
                    self.packet = HLPacket()
                    continue
                if len( self.buffer ) >= 20:
                    size = unpack( "!L" , self.buffer[12:16] )[0]
                    user = self.factory.getUser( self.connID )
                    limit = MAX_PACKET_SIZE if ( user is not None and user.isLoggedIn() ) else MAX_PRELOGIN_PACKET_SIZE
                    if size > limit:
                        self.factory.log.warning( "Oversized packet (%d bytes) from connID=%d, closing" , size , self.connID )
                        self.buffer = b''
                        self.closeConnection()
                        return
                size = self.packet.parse( self.buffer )
                if size > 0:
                    self.buffer = self.buffer[size:]
                    self.handlePacket()
                    self.packet = HLPacket()
                else:
                    done = True
        else:
            if len( self.buffer ) > MAX_IRC_LINE:
                # Still no Hotline magic or IRC registration: not a client.
                self.buffer = b''
                self.closeConnection()
                return
            if len( self.buffer ) >= 12:
                ( proto , subProto , vers , subVers ) = unpack( "!LLHH" , self.buffer[0:12] )
                if proto == HLCharConst( "TRTP" ):
                    self.buffer = self.buffer[12:]
                    self.gotMagic = True
                    self.send( pack( "!2L" , HLCharConst( "TRTP" ) , 0 ) )
                    # If there is still data in the buffer, check for packets.
                    if len( self.buffer ) > 0:
                        self.parseBuffer()
                    return
                else:
                    # Not hotline, assume IRC. Multiple commands can be chained in IRC.
                    # Only look at complete lines; CAP and PASS may precede NICK/USER.
                    text = self.buffer.decode( 'mac-roman' )
                    cmds = [ c.rstrip( "\r" ) for c in text.split( "\n" )[:-1] ]
                    names = [ c.split( " " , 1 )[0].upper() for c in cmds ]
                    if ( "NICK" not in names ) and ( "USER" not in names ):
                        if not cmds:
                            # Wait for a complete line.
                            return
                        unexpected = [ n for n in names if n not in ( "CAP" , "PASS" ) ]
                        if unexpected:
                            self.ircWrite( ":"+IRC_SERVER_NAME+" 421 %s :Unknown command\r\n" % unexpected[0] )
                            self.closeConnection()
                            return
                        # Only capability negotiation / server password so far:
                        # answer CAP LS and wait for the client to register.
                        self.ircReplyCapLS( cmds )
                        return
                    nick = "Unnamed"
                    for c in cmds:
                        parts = c.split( " " , 1 )
                        if parts[0].upper() == "NICK" and len( parts ) > 1 and parts[1].strip( ": " ):
                            nick = cleanNick( parts[1].strip( ": " ) )[:MAX_NICK_LEN] or "Unnamed"
                            break
                    # Answer CAP LS before the welcome so clients finish negotiation.
                    self.ircReplyCapLS( cmds )
                    user = self.factory.getUser( self.connID )
                    user.nick = nick # Making sure we have the right nick.
                    self.ircWrite( "NOTICE * :*** Welcome to Hotline\r\n" )
                    self.ircWrite( "NOTICE AUTH :*** You are NOT logged in\r\n" )
                    self.ircWrite( "NOTICE AUTH :*** Log in with '/msg NickServ IDENTIFY <login> <password>', a server password of '<login>:<password>', or '/msg loginserv <login> <password>'.\r\n" )
                    if IRC_GUEST_LOGIN_DELAY > 0:
                        self.ircWrite( "NOTICE AUTH :*** Otherwise you will be logged in as guest in %d seconds.\r\n" % IRC_GUEST_LOGIN_DELAY )
                    else:
                        self.ircWrite( "NOTICE AUTH :*** If you do not have an account, use '/msg loginserv guest' to proceed.\r\n" )
                    self.ircWrite( ":"+IRC_SERVER_NAME+" 001 %s :Waiting for login input..\r\n" % nick )
                    self.ircWrite( ":"+IRC_SERVER_NAME+" 375 %s :- MOTDs are for losers.\r\n" % user.nick )
                    self.ircWrite( ":"+IRC_SERVER_NAME+" 372 %s :- :)\r\n" % user.nick )
                    self.ircWrite( ":"+IRC_SERVER_NAME+" 376 %s :End of /MOTD command.\r\n" % user.nick )

                    self.isIRC = True
                    self.gotMagic = True
                    if IRC_GUEST_LOGIN_DELAY > 0:
                        self.guestTimer = reactor.callLater( IRC_GUEST_LOGIN_DELAY , self.ircAutoGuest )
                    self.parseBuffer()

    def pauseProducing( self ):
        # Twisted calls this on every write while the buffer is full: only
        # start counting when the client goes from reading to not reading.
        if not self.outputPaused:
            self.outputPaused = True
            self.pausedBytes = 0

    def resumeProducing( self ):
        self.outputPaused = False
        self.pausedBytes = 0

    def stopProducing( self ):
        pass

    def closeConnection( self ):
        try:
            self.transport.unregisterProducer()
        except Exception:
            pass
        GracefulCloseMixin.closeConnection( self )

    def send( self , data ):
        """ Writes ``data`` to the client, unless it has stopped reading:
        then it is disconnected once MAX_PENDING_OUTPUT bytes are waiting. """
        if self.closing:
            return
        if isinstance( data , str ):
            data = data.encode( 'mac-roman' , errors = 'replace' )
        if not data:
            return
        if self.outputPaused:
            self.pausedBytes += len( data )
            if self.pausedBytes > MAX_PENDING_OUTPUT:
                self.factory.log.info( "Client not reading its data (connID=%d), disconnecting" , self.connID )
                self.closing = True
                if hasattr( self.transport , "abortConnection" ):
                    self.transport.abortConnection()
                else:
                    self.transport.loseConnection()
                return
        self.transport.write( data )

    def ircWrite( self , text ):
        """ Writes a line of IRC text (str) to the client. Twisted's
        transport.write requires bytes in Python 3. """
        self.send( text.encode( 'mac-roman' , errors = 'replace' ) )

    def ircNotice( self , text , sender = NICKSERV_PREFIX ):
        """ Sends a NOTICE to this IRC client. """
        user = self.factory.getUser( self.connID )
        nick = ( user and user.nick ) or "*"
        self.ircWrite( "%s NOTICE %s :%s\r\n" % ( sender , nick , text ) )

    def ircReplyCapLS( self , cmds ):
        """ Replies to a CAP LS found among the handshake lines, if any. """
        for c in cmds:
            parts = c.split( " " , 2 )
            if parts[0].upper() == "CAP" and len( parts ) > 1 and parts[1].upper() == "LS":
                self.ircHandleCap( "LS" , "" , "*" )

    def ircHandleCap( self , sub , arg , nick ):
        """ Minimal IRCv3 capability negotiation: we support no capabilities. """
        if sub == "LS":
            if not self.capReplied:
                self.capReplied = True
                self.ircWrite( ":"+IRC_SERVER_NAME+" CAP %s LS :\r\n" % nick )
        elif sub == "REQ":
            if arg.startswith( ":" ):
                arg = arg[1:]
            self.ircWrite( ":"+IRC_SERVER_NAME+" CAP %s NAK :%s\r\n" % ( nick , arg ) )

    def ircAutoGuest( self ):
        """ Logs an IRC client in as guest if it has not logged in by itself. """
        self.guestTimer = None
        user = self.factory.getUser( self.connID )
        if ( not user ) or user.isLoggedIn() or self.closing:
            return
        if self.factory.database.loadAccount( "guest" ) == None:
            self.ircNotice( "No guest account on this server, please IDENTIFY to log in." )
            return
        packet = HLPacket( HTLC_HDR_LOGIN , 0 , 0 , 1 )
        packet.addString( DATA_LOGIN , HLEncode( "guest" ) )
        packet.addString( DATA_PASSWORD , HLEncode( "" ) )
        user.isIRC = True
        user.lastPacketTime = time.time()
        try:
            self.factory.dispatchPacket( self.connID , packet )
        except HLException as ex:
            # Don't disconnect; the client can still IDENTIFY.
            self.ircNotice( "Guest login failed: %s" % ex.msg )
    
    def handlePacket( self ):
        """ Dispatch the packet to the factory (and its listeners) and check to see if we should update our away status. """
        try:
            user = self.factory.getUser( self.connID )
            if not user:
                self.closeConnection()
                return
            if not user.isLoggedIn():
                # Clients log in first; a connection that keeps sending
                # other things instead is just using up the server.
                self.preLoginPackets += 1
                if self.preLoginPackets > MAX_PRELOGIN_PACKETS:
                    self.factory.log.info( "Too many packets before login (connID=%d), closing" , self.connID )
                    self.closeConnection()
                    return
            if self.isIRC and self.packet.irccap:
                self.ircHandleCap( self.packet.irccap[0] , self.packet.irccap[1] , user.nick )
                return
            if self.isIRC and self.packet.ircreply:
                self.ircWrite( self.packet.ircreply )
            if self.isIRC and self.packet.irctrap:
                # Unsupported command, return 421
                self.send(
                    ( ":"+IRC_SERVER_NAME+" 421 %s %s :Unknown command\r\n" % (user.nick, self.packet.irctrap) ).encode( 'mac-roman' )
                )
                return
            if self.isIRC and self.packet.type == 0:
                # Consumed IRC line with nothing to dispatch (PONG, LAGTIME, ...).
                # Ignore it so it neither errors nor resets the idle timer.
                return
            if user.isLoggedIn():
                # Make sure we're logged in before doing anything.
                self.factory.dispatchPacket( self.connID , self.packet )
                if ( not isPingType( self.packet.type ) ) and ( not user.away ):
                    # We got a non-ping packet, and we're not away.
                    user.lastPacketTime = time.time()
                    if ( self.idleTimer != None ) and self.idleTimer.active():
                        # If the idleTimer exists and hasn't fired yet, remain active.
                        self.idleTimer.reset( IDLE_TIME )
                    else:
                        # Otherwise, we just came back from being idle.
                        user.status &= ~STATUS_AWAY
                        self.factory.dispatchPacket( self.connID , HLPacket( HTLC_HDR_USER_CHANGE ) )
                        self.idleTimer = reactor.callLater( IDLE_TIME , self.idleCheck )
            elif ( self.packet.type == HTLC_HDR_LOGIN ):
                user.isIRC = self.packet.isIRC
                # If we're not logged in, only dispatch login packets.
                user.lastPacketTime = time.time()
                self.factory.dispatchPacket( self.connID , self.packet )
            elif ( self.packet.type == HTLC_HDR_PING ):
                if self.packet.isIRC:
                    self.factory.dispatchPacket( self.connID , self.packet )
            else:
                if ( self.packet.isIRC == 0 ) and ( self.packet.type != 0 ) and ( self.packet.type != 130 ):
                    # Debug only: anyone can send these, as fast as they like.
                    self.factory.log.debug( "packet before login (connID=%d): %s" , self.connID , self.packet )
        except HLException as ex:
            # Unhandled packets and task errors will be caught here. These
            # are ordinary refusals ("You are not allowed...", "Please
            # wait..."), which anyone can trigger over and over: only log
            # them when debugging (failed logins are logged on their own).
            self.factory.log.debug(
                "HLException on connID=%d packet.type=0x%x fatal=%s: %s" ,
                self.connID , self.packet.type , ex.fatal , ex.msg
            )
            if self.isIRC and self.packet.type == HTLC_HDR_LOGIN:
                self.ircNotice( "Login failed: %s" % ex.msg )
            elif self.isIRC:
                if self.packet.irctrap:
                    # Not sure this is still required since we already return a 421 "Unknown command" reply.
                    self.send(
                        ( "NOTICE * :*** HL Error 0x%x [%s] %s\r\n" % ( self.packet.type, self.packet.irctrap, ex.msg ) ).encode( 'mac-roman' )
                    )
            else:
                packet = HLPacket( HTLS_HDR_TASK , self.packet.seq , 1 )
                packet.addString( DATA_ERROR , ex.msg )
                self.writePacket( packet )
            if ex.fatal:
                # The exception was fatal (i.e. failed login) so kill the connection.
                self.closeConnection()
        except Exception:
            # Anything else is a bug — surface it instead of letting Twisted
            # eat it.
            self.factory.log.exception( "Unhandled error in handlePacket (connID=%d)" , self.connID )
            self.closeConnection()
    
    def loginTimeoutCheck( self ):
        """ Closes the connection if it still hasn't logged in. """
        self.loginTimer = None
        user = self.factory.getUser( self.connID )
        if ( user is None ) or ( not user.isLoggedIn() ):
            self.factory.log.info( "Login timeout (connID=%d), closing" , self.connID )
            self.closeConnection()

    def idleCheck( self ):
        """ Called a set amount of time after the last non-ping packet, mark us as idle and trick the handlers into sending the change. """
        user = self.factory.getUser( self.connID )
        if ( user is not None ) and user.isLoggedIn() and not user.away:
            # Only send the change if the user is not away and not idle.
            user.status |= STATUS_AWAY
            self.factory.dispatchPacket( self.connID , HLPacket(HTLC_HDR_USER_CHANGE ) )
        del self.idleTimer
        self.idleTimer = None
    
    def writePacket( self , packet ):
        """ Flattens and writes a packet out to the socket. """
        packet.server = self.factory
        flat = packet.flatten( self.factory.getUser( self.connID ) )
        try:
            self.factory.log.debug(
                "writePacket connID=%d type=0x%x seq=%d nfields=%d len=%d hex=%s" ,
                self.connID , packet.type , packet.seq ,
                len( packet.objs ) , len( flat ) ,
                flat.hex() if isinstance( flat , (bytes , bytearray) ) else '<not bytes>' ,
            )
        except Exception:
            pass
        self.send( flat )

class HLServer( Factory ):
    """ Factory subclass that handles all global server operations. Also owns database and fileserver objects. """
    
    def __init__( self ):
        self.port = SERVER_PORT
        self.lastUID = 0
        self.lastChatID = 0
        self.clients = {}
        self.chats = {}
        self.handlers = []
        self.tempBans = {}
        # Recent failed login times, per IP address.
        self.loginFailures = {}
        # Recent event times for rate limits, per ( kind , key ).
        self.rateEvents = {}
        # Addresses standing for many clients: no per-address limits/bans.
        self.shared = sharedAddresses()
        self.warnedShared = False
        self.database = getDatabase( DB_TYPE )
        self.fileserver = HLFileServer( self )
        self.webserver = HLWebServices( self )
        self.startTime = time.time()
        self.log = logging.getLogger( "phxd" )
        self.linker = HLServerLinker( self )
        self._initLog()
        self._ensureFileRoot()
        reactor.listenTCP( self.port , self )
        self.setupTLS( HOTLINE_TLS_PORT , IRC_TLS_PORT , TLS_CERT , TLS_KEY )
        # Update all trackers periodically
        recurrentTask = task.LoopingCall(self.updateTrackers)
        recurrentTask.start(TRACKER_REFRESH_PERIOD)
        #recurrentTask.addErrback(updateTrackersFailed)
    
    def setupTLS( self , hotlinePort , ircPort , certPath , keyPath ):
        """ Starts the TLS listeners: Hotline over TLS on ``hotlinePort``
        with TLS file transfers on the port after it, and IRC over TLS on
        ``ircPort`` (0 disables either). All share one certificate, which
        is reloaded when its files change. Exits with a readable error if
        TLS is enabled but the certificate can't be loaded. Returns the
        context factory, or None when TLS is disabled. """
        ports = [ p for p in ( hotlinePort , ircPort ) if p ]
        if not ports:
            return None
        from server.HLTLS import ReloadingTLSContextFactory , TLSConfigError
        if not certPath or not keyPath:
            raise SystemExit( "phxd: configuration error: a TLS port is set but tls_cert / tls_key are not" )
        try:
            contextFactory = ReloadingTLSContextFactory( certPath , keyPath , self.log )
        except TLSConfigError as e:
            raise SystemExit( "phxd: configuration error: %s" % e )
        # The listener detects Hotline vs IRC per connection, so one
        # listener serves both if the two ports are the same.
        for port in sorted( set( ports ) ):
            reactor.listenSSL( port , self , contextFactory )
            self.log.info( "Listening for TLS connections on port %d" , port )
        if hotlinePort:
            self.fileserver.listenTLS( hotlinePort + 1 , contextFactory )
            self.log.info( "Listening for TLS file transfers on port %d" , hotlinePort + 1 )
        return contextFactory

    def secureDefaultAdmin( self ):
        """ If the "admin" account still has the default password from the
        initial database ("adminpass", published in the README), anyone
        could take full control of the server: replace it with a random
        password, shown once in the log. Returns the new password, or None
        if nothing needed doing. """
        import secrets
        from shared.HLPassword import hashPassword , verifyPassword
        try:
            acct = self.database.loadAccount( "admin" )
        except Exception:
            return None
        if ( acct is None ) or not verifyPassword( acct.password , b"adminpass" ):
            return None
        password = secrets.token_urlsafe( 12 )
        acct.password = hashPassword( password )
        try:
            saved = self.database.saveAccount( acct ) is not False
        except Exception:
            saved = False
        if not saved:
            self.log.warning( "SECURITY: the 'admin' account still has the default password 'adminpass' "
                              "and it could not be replaced. Log in and change it now (or delete the account)." )
            return None
        self.log.warning( "SECURITY: the 'admin' account had the default password 'adminpass', which anyone "
                          "could use. Its password is now: %s  (log in and change it to one of your choice)" , password )
        return password

    def _ensureFileRoot( self ):
        """ Creates the shared files directory if it is missing; otherwise
        every file listing fails with "The specified directory does not
        exist." (e.g. a fresh Docker container without a files mount). """
        if FILE_ROOT and not os.path.isdir( FILE_ROOT ):
            try:
                os.makedirs( FILE_ROOT )
                self.log.info( "Created shared files directory %s" , FILE_ROOT )
            except OSError as e:
                self.log.warning( "Could not create shared files directory %s: %s" , FILE_ROOT , e )

    def updateTrackers(self):
        """Updates the register trackers, if any, with the name
        and description of server and the current user count.
        """
        for hostname, port in TRACKER_LIST:
            # One failing tracker must not raise out of the LoopingCall,
            # which would stop all future tracker updates.
            try:
                reactor.listenUDP(0, HLTrackerClient(self, hostname, port))
            except Exception as e:
                self.logEvent(LOG_TYPE_TRACKER, "Failed to update tracker {}:"
                              " {}".format(hostname, e))

    def updateTrackersFailed(self, reason):
        """Errback invoked when the task to update the trackers
        fails for whatever reason.
        """
        print("Failed to update tracker: reason")

    def _initLog( self ):
        import os, sys
        self.log.setLevel( logging.DEBUG )
        # Don't propagate to the root logger — we attach our own handlers.
        self.log.propagate = False
        for old in [ f for f in self.log.filters if isinstance( f , LogRateLimiter ) ]:
            self.log.removeFilter( old )
        self.log.addFilter( LogRateLimiter( self.log , LOG_LINES_PER_MINUTE ) )

        fmt = logging.Formatter( '%(asctime)s\t%(levelname)s\t%(message)s' )

        # Always stream to stdout so ``docker logs`` shows server activity.
        # Without this, every log call goes to a file inside the container
        # (or, worse, nowhere at all when ENABLE_FILE_LOG is off).
        streamHandler = logging.StreamHandler( sys.stdout )
        streamHandler.setFormatter( fmt )
        streamHandler.setLevel( getattr( logging , LOG_LEVEL , logging.INFO ) )
        self.log.addHandler( streamHandler )

        if ENABLE_FILE_LOG:
            # NOTE: the previous version had setFormatter/addHandler nested
            # inside the ``except IOError`` branch, so the rotating file
            # handler was created but never attached when the log dir
            # already existed. Also, ``logging.FileHandler`` doesn't take
            # ``maxBytes``/``backupCount`` — keep ``RotatingFileHandler``
            # for both branches.
            logSizeBytes = LOG_MAX_SIZE_MBYTES * 1024 * 1024
            log_dir = os.path.dirname( LOG_FILE )
            if log_dir and not os.path.isdir( log_dir ):
                try:
                    os.makedirs( log_dir )
                except OSError:
                    pass
            try:
                fileHandler = RotatingFileHandler(
                    LOG_FILE,
                    maxBytes=logSizeBytes,
                    backupCount=MAX_LOG_FILES,
                )
                fileHandler.setFormatter( fmt )
                fileHandler.setLevel( getattr( logging , LOG_LEVEL , logging.INFO ) )
                self.log.addHandler( fileHandler )
            except (IOError, OSError) as e:
                self.log.warning( "Could not open log file %s: %s" , LOG_FILE , e )

            # Database event log (info+).
            try:
                dbHandler = HLDatabaseLogger( self.database )
                dbHandler.setLevel( logging.INFO )
                self.log.addHandler( dbHandler )
            except Exception as e:
                self.log.warning( "Could not attach database log handler: %s" , e )

        # Bridge Twisted's own logging system to Python logging so
        # connection/handshake errors and tracebacks from inside Twisted
        # callbacks (e.g. unhandled exceptions in ``dataReceived``) show
        # up in ``docker logs`` instead of being silently swallowed.
        try:
            from twisted.python import log as twisted_log
            twisted_logger = logging.getLogger( "twisted" )
            twisted_logger.setLevel( logging.DEBUG )
            twisted_logger.propagate = False
            twisted_logger.addHandler( streamHandler )

            def _bridge( eventDict ):
                if eventDict.get( "isError" ):
                    msg = twisted_log.textFromEventDict( eventDict ) or ""
                    twisted_logger.error( "%s" , msg )
                else:
                    # Twisted's informational messages ("Starting protocol",
                    # "(UDP Port ... Closed)", ... several per tracker update)
                    # are only useful when debugging.
                    msg = twisted_log.textFromEventDict( eventDict )
                    if msg:
                        twisted_logger.debug( "%s" , msg )

            twisted_log.addObserver( _bridge )
        except Exception as e:
            self.log.warning( "Could not bridge Twisted log: %s" , e )
        
    def linkToServer( self, addr ):
        ( ip , port ) = addr.split( ':' )
        self.linker.link( ip, int(port) )

    def nextUID( self ):
        """ Returns an unused user ID. User IDs are 16-bit on the wire, so
        they wrap around within 1..65535 instead of growing with every
        connection the server ever accepted (which, past 65535, broke the
        user list for everyone). """
        for _ in range( 0xFFFF ):
            self.lastUID = ( self.lastUID % 0xFFFF ) + 1
            if self.lastUID not in self.clients:
                return self.lastUID
        raise RuntimeError( "no free user ID" )

    def addRemoteUser( self, remoteUser, sendChange = True ):
        self.nextUID()
        user = HLUser( self.lastUID, "<linked ip>" )
        user.nick = remoteUser.nick
        user.icon = remoteUser.icon
        user.color = remoteUser.color
        user.status = remoteUser.status
        user.local = False
        user.account = HLAccount( "<linked account>" )
        user.account.name = "Linked Account"
        user.valid = True

        self.clients[self.lastUID] = ( None , user )

        if sendChange:
            change = HLPacket( HTLS_HDR_USER_CHANGE )
            change.addNumber( DATA_UID , user.uid )
            change.addString( DATA_NICK , user.nick )
            change.addNumber( DATA_ICON , user.icon )
            change.addNumber( DATA_STATUS , user.status )
            for ( conn , user ) in self.clients.values():
                if user.local:
                    conn.writePacket( change )
        return user.uid

    def removeRemoteUser( self, uid ):
               if uid in self.clients:
                       del( self.clients[uid] )
    
    def handleUserLogin( self, user ):
               user.valid = True
               self.linker.forwardUserConnect( user )

    
    def isShared( self , addr ):
        """ True if addr stands for many clients (see SHARED_ADDRESSES):
        limiting or banning it would hit all of them. Warns once. """
        if addr not in self.shared:
            return False
        if not self.warnedShared:
            self.warnedShared = True
            self.log.warning( "Clients are connecting from %s, which stands for many clients (e.g. Docker "
                              "forwarding IPv6 connections): per-address limits and bans are not applied to it. "
                              "See SHARED_ADDRESSES in README.md to give phxd the real addresses." , addr )
        return True

    def addTempBan( self , addr , reason = "no reason" ):
        """ Adds a temporary ban for addr that will expire in BAN_TIME seconds. """
        if self.isShared( addr ):
            self.log.warning( "Not banning %s: it stands for many clients" , addr )
            return
        now = time.time()
        if self._activeBan( addr , now ) is not None:
            return
        # Store the expiry time instead of scheduling a timer per ban, in
        # a table kept in expiry order and bounded like the others (an
        # attacker with many addresses could otherwise grow it at will).
        self.tempBans.pop( addr , None )
        self.tempBans[addr] = ( reason , now + BAN_TIME )
        while self.tempBans:
            first = next( iter( self.tempBans ) )
            if ( len( self.tempBans ) > MAX_TRACKED_KEYS ) or ( self.tempBans[first][1] <= now ):
                del self.tempBans[first]
            else:
                break

    def _activeBan( self , addr , now ):
        """ The reason addr is temporarily banned, or None. """
        entry = self.tempBans.get( addr )
        if entry is None:
            return None
        if entry[1] <= now:
            del self.tempBans[addr]
            return None
        return entry[0]
    
    def removeTempBan( self , addr ):
        """ Removes a temporary ban for addr, if it exists. """
        if addr in self.tempBans:
            del self.tempBans[addr]
    
    def recordLoginFailure( self , addr ):
        """ Counts a failed login from addr, and bans addr for BAN_TIME once
        it has failed MAX_LOGIN_FAILURES times in LOGIN_FAILURE_WINDOW. """
        if ( MAX_LOGIN_FAILURES <= 0 ) or self.isShared( addr ):
            return
        now = time.time()
        recent = [ t for t in self.loginFailures.pop( addr , [] ) if now - t < LOGIN_FAILURE_WINDOW ]
        recent.append( now )
        # (Re)inserted last: the dict stays ordered by most recent failure,
        # so the oldest entries are at the front.
        self.loginFailures[addr] = recent
        self._trim( self.loginFailures , now , LOGIN_FAILURE_WINDOW )
        if len( recent ) >= MAX_LOGIN_FAILURES:
            self.log.warning( "Banning %s for %d seconds after %d failed logins" , addr , BAN_TIME , len( recent ) )
            self.addTempBan( addr , "Too many failed logins." )
            self.loginFailures.pop( addr , None )

    def allowRate( self , kind , key , limit , window ):
        """ Records an event of ``kind`` for ``key`` (an address, a user)
        and returns False if there were already ``limit`` of them in the
        last ``window`` seconds (the event is then not counted). A limit
        of 0 or less means unlimited. """
        if limit <= 0:
            return True
        now = time.time()
        recent = [ t for t in self.rateEvents.pop( ( kind , key ) , [] ) if now - t < window ]
        allowed = len( recent ) < limit
        if allowed:
            recent.append( now )
        # (Re)inserted last, so the dict stays ordered by last activity.
        self.rateEvents[( kind , key )] = recent
        self._trim( self.rateEvents , now , 60 )
        return allowed

    def _trim( self , table , now , window ):
        """ Keeps ``table`` (key -> event times, ordered oldest activity
        first) bounded: drops leading entries that are older than
        ``window`` or beyond MAX_TRACKED_KEYS. Only the expired or excess
        entries at the front are looked at, so this is cheap. """
        while table:
            key = next( iter( table ) )
            times = table[key]
            if ( len( table ) > MAX_TRACKED_KEYS ) or ( not times ) or ( now - times[-1] >= window ):
                del table[key]
            else:
                break

    def logFull( self ):
        """ Logs (at most once a minute) that connections are refused
        because MAX_CONNECTIONS_TOTAL is reached. """
        if self.allowRate( "full-log" , None , 1 , 60 ):
            self.log.warning( "Refusing connections: %d connections already open (max_connections_total)" , MAX_CONNECTIONS_TOTAL )

    def allowConnect( self , addr ):
        """ False if addr opened MAX_CONNECTS_PER_MINUTE connections in the
        last minute. Logs once when an address starts being refused. """
        if self.isShared( addr ):
            return True
        if self.allowRate( "connect" , addr , MAX_CONNECTS_PER_MINUTE , 60 ):
            return True
        if self.allowRate( "connect-refused-log" , addr , 1 , 60 ):
            self.log.warning( "Refusing connections from %s for a while: more than %d per minute" , addr , MAX_CONNECTS_PER_MINUTE )
        return False

    def tooManyConnections( self , addr ):
        """ True if addr has more than MAX_CONNECTIONS_PER_IP connections. """
        if ( MAX_CONNECTIONS_PER_IP <= 0 ) or self.isShared( addr ):
            return False
        count = len( [ u for ( c , u ) in self.clients.values() if u.local and u.ip == addr ] )
        return count > MAX_CONNECTIONS_PER_IP

    def checkForBan( self , addr ):
        """ Returns the reason given for a ban, if it exists. Otherwise returns None. """
        reason = self._activeBan( addr , time.time() )
        if reason is not None:
            return reason
        return self.database.checkBanlist( addr )
    
    def buildProtocol( self , addr ):
        """ Called when the factory accepts a connection and is asked to return a Protocol (in our case, a HLConnection). """
        self.nextUID()
        conn = HLConnection( self , self.lastUID )
        user = HLUser( self.lastUID , addr.host )
        self.clients[self.lastUID] = ( conn , user )
        for handler in self.handlers:
            handler.handleUserConnected( self , user )
        return conn
    
    def registerPacketHandler( self , handler ):
        """ Registers a HLPacketHandler. """
        if isinstance( handler , HLPacketHandler ):
            self.handlers.append( handler )
    
    def disconnectUser( self , uid ):
        """ Actively disconnect the specified user. """
        if uid in self.clients:
            ( conn , user ) = self.clients[uid]
            conn.closeConnection()
    
    def removeConnection( self , connID ):
        """ Called from HLConnection when a connection dies. """
        if connID in self.clients:
            ( conn , user ) = self.clients[connID]
            if user.isLoggedIn():
                for handler in self.handlers:
                    handler.handleUserDisconnected( self , user )
                self.fileserver.cleanupTransfers( user.uid )
                self.linker.forwardUserDisconnect( user )
            del( self.clients[connID] )
    
    def getUser( self , uid ):
        """ Gets the HLUser object for the specified uid. """
        if uid in self.clients:
            ( conn , user ) = self.clients[uid]
            return user
        return None

    def getUserCount( self ):
        """ Returns the number of logged in HLUsers. """
        # NOTE: this method was previously nested inside ``getUser`` due to
        # over-indentation, which made it unreachable. ``HLTracker`` calls
        # it on every tracker update.
        return len( [user for _, user in self.clients.values() if user.isLoggedIn()] )

    def getOrderedUserlist( self ):
        """ Returns a list of HLUsers, ordered by uid. """
        keys = list(self.clients.keys())
        keys.sort()
        userlist = []
        for uid in keys:
            ( conn , user ) = self.clients[uid]
            if user.isLoggedIn():
                userlist.append( user )
        return userlist
    
    def createChat( self ):
        """ Creates and registers a new private chat, returns the ID of the newly created chat. """
        self.lastChatID += 1
        chat = HLChat( self.lastChatID )
        self.chats[self.lastChatID] = chat
        return chat
    
    def removeChat( self , id ):
        """ Remove the specified private chat. """
        if id in self.chats:
            del self.chats[id]
    
    def getChat( self , id ):
        """ Gets the HLChat object for the specified chat ID. """
        if id in self.chats:
            return self.chats[id]
        return None
    
    def sendPacket( self , uid , packet ):
        """ Sends the specified packet to the specified user. """
        if uid in self.clients:
            ( conn , user ) = self.clients[uid]
            packet.isIRC = conn.isIRC
            if user.local:
                conn.writePacket( packet )
            else:
                self.linker.forwardPacket( packet, user.uid )
    
    def broadcastPacket( self , packet , priv = 0 ):
        """ Sends the specified packet to all connected users. If priv is specified, only sends to users with that priv. """
        for ( conn , user ) in self.clients.values():
            packet.isIRC = conn.isIRC
            if not user.local:
                self.linker.forwardPacket( packet, user.uid )
            elif user.isLoggedIn():
                if priv > 0:
                    if user.hasPriv( priv ):
                        conn.writePacket( packet )
                else:
                    conn.writePacket( packet )

    def dispatchPacket( self , connID , packet ):
        """ Called from HLConnection to dispatch a packet to all registered packet handlers. """
        if connID in self.clients:
            handled = False
            ( conn , user ) = self.clients[connID]
            for handler in self.handlers:
                handled |= handler.handlePacket( self , user , packet )
            if handled == False:
                # Log the unknown type at INFO so we can spot what clients
                # are sending without flooding stdout with WARNINGs every
                # time a Hotline 1.5+ feature we don't implement gets
                # exercised. The HLException still bubbles up so the
                # client receives an error TASK reply.
                self.log.debug( "unknown packet type 0x%x (seq=%d) from connID=%d — ignoring" , packet.type , packet.seq , connID )
                raise HLException("unknown packet type")

    #def returnClients( self ):
    #	""" For irc :p """
    #	return self.clients
    # DELETEME i think its dead code!!

    def logEvent( self , typeInt , msg , user = None ):
        """ Logs an event. If user is specified, the event will be logged with the users nickname, login, and IP address. """
        login = ""
        nickname = ""
        ip = ""
        if user != None:
            login = user.account.login
            nickname = user.nick
            ip = user.ip
        typeStr = str(typeInt)
        try:
            typeStr = LOG_TYPE_STR_MAP[typeInt]
        except KeyError:
            pass
        # format as <typeStr>\t<message>\t<login>\t<nickname>\t<ip>
        # this is the "message" for the FileLogger
        fmt = "%s\t%s\t%s\t%s\t%s"
        # NOTE: previously compared against the builtin ``type`` instead of
        # the ``typeInt`` parameter, which meant every event went through
        # the ``info`` branch.
        if typeInt == LOG_TYPE_ERROR:
            self.log.error( fmt, typeStr, msg, login, nickname, ip )
        elif typeInt == LOG_TYPE_DEBUG:
            self.log.debug( fmt, typeStr, msg, login, nickname, ip )
        else:
            self.log.info( fmt, typeStr, msg, login, nickname, ip )
    
    def updateAccounts( self , acct ):
        """ Updates the account information for all current users with login matching that of the specified HLAccount. """
        for ( conn , user ) in self.clients.values():
            # Logins are case-sensitive: "Bob" and "bob" are different
            # accounts, and must not get each other's privileges.
            if user.isLoggedIn() and user.local and ( user.account.login == acct.login ):
                user.account.copyFrom( acct )
                self.dispatchPacket( user.uid , HLPacket( HTLC_HDR_USER_CHANGE ) )

    def disconnectAccount( self , login ):
        """ Disconnects everyone logged in with ``login`` (e.g. after the
        account was deleted or renamed, so its privileges end now). """
        for ( conn , user ) in list( self.clients.values() ):
            if user.isLoggedIn() and user.local and ( user.account.login == login ):
                conn.closeConnection()
