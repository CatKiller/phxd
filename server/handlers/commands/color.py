from __future__ import absolute_import
from shared.HLProtocol import *
def handle( server , user , arg , ref ):
    if len( arg ) > 0:
        try:
            value = int( arg ) & 0xFFFF
        except ValueError:
            return
        # The admin flag is not the user's to set or clear.
        status = ( value & ~STATUS_ADMIN ) | ( user.status & STATUS_ADMIN )
        if user.status != status:
            user.status = status
            server.dispatchPacket( user.uid, HLPacket(HTLC_HDR_USER_CHANGE) )
