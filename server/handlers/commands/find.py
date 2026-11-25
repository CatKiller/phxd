from __future__ import absolute_import
from shared.HLProtocol import *
import os

FIND_MAX_ENTRIES = 20000
FIND_MAX_MATCHES = 100

def handle( server , user , arg , ref ):
    if len( arg ) > 0:
        pre = len( user.account.fileRoot )
        matches = []
        # The walk runs on the server's only thread: bound it so a search
        # of a large share can't stall everyone.
        visited = 0
        stopped = False
        for ( root , dirs , files ) in os.walk( user.account.fileRoot ):
            if not user.hasPriv( PRIV_VIEW_DROPBOXES ):
                # Don't search (or reveal the contents of) drop boxes.
                dirs[:] = [ d for d in dirs if "DROP BOX" not in d.upper() ]
            entries = [ ( "+ " , name ) for name in dirs ] + [ ( "- " , name ) for name in files ]
            for ( prefix , name ) in entries:
                visited += 1
                if ( visited > FIND_MAX_ENTRIES ) or ( len( matches ) >= FIND_MAX_MATCHES ):
                    stopped = True
                    break
                if arg.upper() in name.upper():
                    matches.append( prefix + os.path.join( root , name )[pre:] )
            if stopped:
                matches.append( "(search stopped: too many files or matches)" )
                break
        found = "(none)"
        if len( matches ) > 0:
            found = "\r > ".join( matches )
        matchStr = "\r > --- search results for '%s' ------------\r > %s" % ( arg , found )
        chat = HLPacket( HTLS_HDR_CHAT )
        chat.addString( DATA_STRING , matchStr )
        if ref > 0:
            chat.addInt32( DATA_CHATID , ref )
        server.sendPacket( user.uid , chat )
