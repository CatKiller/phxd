from __future__ import absolute_import
from twisted.internet.protocol import Factory , Protocol
from twisted.internet.interfaces import IProducer
from twisted.internet import reactor
from shared.HLProtocol import *
from server.HLDatabase import *
from shared.HLTypes import *
from shared.HLTransfer import *
from config import *
from server.HLTLS import GracefulCloseMixin
import os
import secrets

class HLTransferConnection( GracefulCloseMixin , Protocol ):
    #__implements__ = Protocol.__implements__ + ( IProducer , )
    
    def connectionMade( self ):
        self.info = None
        self.gotMagic = False
        # Twisted hands raw bytes to ``dataReceived``; keep the buffer
        # bytes so concatenation and unpack on it both work in Py3.
        self.buffer = b""
        # A connection that doesn't say which transfer it is for within
        # XFER_START_TIMEOUT is dropped, and an address may only hold
        # as many of these as it may hold server connections.
        self.startTimer = reactor.callLater( XFER_START_TIMEOUT , self._startTimeout )
        try:
            self.peerHost = self.transport.getPeer().host
        except Exception:
            self.peerHost = None
        if not self.factory.addConnection( self.peerHost ):
            self.closeConnection()

    def _startTimeout( self ):
        self.startTimer = None
        if not self.gotMagic:
            self.closeConnection()

    def connectionLost( self , reason ):
        self.connectionClosed()
        if ( self.startTimer is not None ) and self.startTimer.active():
            self.startTimer.cancel()
        self.factory.removeConnection( self.peerHost )
        if self.info != None:
            self.info.finish()
            self.factory.removeTransfer( self.info.id )
    
    def dataReceived( self , data ):
        """ Called when the transfer connection receives data. Should only happen
        for uploads, and for the 16-byte magic header for all transfers. """
        if self.closing:
            return
        if self.gotMagic:
            if ( self.info != None ) and ( self.info.type == XFER_TYPE_UPLOAD ):
                self.info.parseData( data )
                if self.info.isComplete():
                    # The upload is done: store the file now (finish() is
                    # safe to call again from connectionLost) rather than
                    # when the connection is gone, which over TLS waits for
                    # the client's close_notify. Then close the connection.
                    self.info.finish()
                    self.closeConnection()
            else:
                self.closeConnection()
        else:
            # Make sure we buffer at this point in case we don't get the
            # HTXF magic all at once, or get more than just the magic.
            self.buffer += data
            if len( self.buffer ) >= 16:
                if ( self.startTimer is not None ) and self.startTimer.active():
                    self.startTimer.cancel()
                self.startTimer = None
                # We got the HTXF magic, parse it.
                ( proto , xfid , size , flags ) = unpack( "!4L" , self.buffer[0:16] )
                self.buffer = self.buffer[16:]
                self.gotMagic = True
                self.info = self.factory.findTransfer( xfid )
                if ( self.info != None ) and not self.factory.isFromOwner( self.info , self.transport ):
                    # Only the user who asked for the transfer may run it.
                    self.factory.server.log.warning( "Transfer %d claimed from a different address, refused" , xfid )
                    self.info = None
                if self.info == None:
                    # Invalid xfer ID, kill the connection.
                    self.closeConnection()
                else:
                    if self.info.type == XFER_TYPE_UPLOAD:
                        if self.info.total == 0:
                            self.info.total = size
                        # The request may not have said how big the upload
                        # is; check again now that the size is known.
                        if not hasFreeSpace( os.path.dirname( self.info.path ) or "." , self.info.total ):
                            self.factory.server.log.warning( "Upload %d refused: not enough disk space for %d bytes" , xfid , self.info.total )
                            self.info.claimed = True
                            self.closeConnection()
                            return
                    elif self.info.type == XFER_TYPE_DOWNLOAD:
                        self.transport.registerProducer( self , False )
                    # Cancel the xfer timeout and start it up. The transfer
                    # is now taken: nobody else can claim the same ID.
                    self.factory.cancelTimeout( self.info.id )
                    self.info.claimed = True
                    self.info.start()
                if len( self.buffer ) > 0:
                    # Recurse for any remaining data with gotMagic = True.
                    self.dataReceived( self.buffer )
    
    def resumeProducing( self ):
        """ The transport asked us for more data. Should only happen for
        downloads after we've been registered as a producer. """
        chunk = self.info.getDataChunk()
        if len( chunk ) > 0:
            self.transport.write( chunk )
        else:
            self.transport.unregisterProducer()
    
    def pauseProducing( self ):
        pass
    
    def stopProducing( self ):
        pass

class HLFileServer (Factory):
    protocol = HLTransferConnection
    
    def __init__( self , server ):
        self.port = SERVER_PORT + 1
        self.server = server
        self.lastTransferID = 0
        self.transfers = {}
        self.timeouts = {}
        # Open transfer connections, per peer address.
        self.connections = {}
        reactor.listenTCP( self.port , self )

    def listenTLS( self , port , contextFactory ):
        """ Accepts file transfers over TLS on ``port`` too. """
        reactor.listenSSL( port , self , contextFactory )
    
    def addConnection( self , host ):
        """ Counts a new transfer connection from ``host``; returns False
        if that is more than MAX_CONNECTIONS_PER_IP. """
        self.connections[host] = self.connections.get( host , 0 ) + 1
        if self.server.isShared( host ):
            return True
        return ( MAX_CONNECTIONS_PER_IP <= 0 ) or ( self.connections[host] <= MAX_CONNECTIONS_PER_IP )

    def removeConnection( self , host ):
        count = self.connections.get( host , 0 ) - 1
        if count > 0:
            self.connections[host] = count
        else:
            self.connections.pop( host , None )

    def checkTransferLimit( self , owner ):
        """ Raises HLException if ``owner`` already has
        MAX_TRANSFERS_PER_USER transfers (each holds an open file). """
        if len( self.findTransfersForUser( owner ) ) >= MAX_TRANSFERS_PER_USER:
            raise HLException( "Too many file transfers at once, please wait for some to finish." )

    def newTransferID( self ):
        """ Returns an unused, unpredictable transfer ID. IDs used to count
        up from 1, so anyone could guess the next one and connect to the
        transfer port first to take over someone else's transfer. """
        while True:
            xfid = secrets.randbelow( 0x7FFFFFFF ) + 1
            if xfid not in self.transfers:
                self.lastTransferID = xfid
                return xfid

    def isFromOwner( self , info , transport ):
        """ True if ``transport`` comes from the address of the user who
        requested transfer ``info``, and the transfer isn't already taken. """
        if getattr( info , "claimed" , False ):
            return False
        owner = self.server.getUser( info.owner )
        if owner is None:
            return False
        try:
            host = transport.getPeer().host
        except Exception:
            return False
        return host == owner.ip

    def addUpload( self , owner , path ):
        """ Adds an upload to the list of transfers. """
        self.checkTransferLimit( owner )
        info = HLUpload( self.newTransferID() , path , owner )
        self.transfers[self.lastTransferID] = info
        self.timeouts[info.id] = reactor.callLater( XFER_START_TIMEOUT , self.timeoutTransfer , info.id )
        return info
    
    def addDownload( self , owner , path , offset ):
        """ Adds a download to the list of transfers. """
        self.checkTransferLimit( owner )
        info = HLDownload( self.newTransferID() , path , owner , offset )
        self.transfers[self.lastTransferID] = info
        self.timeouts[info.id] = reactor.callLater( XFER_START_TIMEOUT , self.timeoutTransfer , info.id )
        return info
    
    def findTransfer( self , xfid ):
        """ Returns the HLTransfer (HLDownload or HLUpload) object for the specified transfer ID. """
        if xfid in self.transfers:
            return self.transfers[xfid]
        return None
    
    def findTransfersForUser( self , uid ):
        """ Returns a list of all transfers for the specified user ID. """
        xfers = []
        for info in self.transfers.values():
            if info.owner == uid:
                xfers.append( info )
        return xfers
    
    def cancelTimeout( self , id ):
        """ Cancels a pending timeout for the specified transfer. """
        if id in self.timeouts:
            self.timeouts[id].cancel()
            del self.timeouts[id]
    
    def timeoutTransfer( self , id ):
        """ Called after an initial timeout to remove the dead transfer from the list of transfers. """
        self.timeouts.pop( id , None )
        if id in self.transfers:
            # Close its file: transfers open it when they are requested.
            self.transfers.pop( id ).finish()
    
    def removeTransfer( self , xfid ):
        """ Removes a transfer from the list of transfers. """
        if xfid in self.transfers:
            info = self.transfers[xfid]
            user = self.server.getUser( info.owner )
            if user != None:
                if info.isComplete():
                    type = ( "Download" , "Upload" )[info.type]
                    speed = "%d k/sec" % ( info.getTotalBPS() // 1024 )
                    msg = "%s of '%s' complete (%s)" % ( type , info.name , speed )
                    self.server.logEvent( LOG_TYPE_TRANSFER , msg , user )
                if info.type == XFER_TYPE_DOWNLOAD:
                    self.server.database.updateAccountStats( user.account.login , info.transferred , 0 )
                elif info.type == XFER_TYPE_UPLOAD:
                    self.server.database.updateAccountStats( user.account.login , 0 , info.transferred )
            del self.transfers[info.id]
    
    def cleanupTransfers( self , owner ):
        """ Removes any transfers owned by owner. Should be called when the user disconnects or is disconnected. """
        for xfer in list( self.transfers.values() ):
            if xfer.owner == owner:
                self.removeTransfer( xfer.id )
