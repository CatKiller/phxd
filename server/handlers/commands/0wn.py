from __future__ import absolute_import
from shared.HLProtocol import *

def handle( server , user , arg , ref):
    chat = HLPacket( HTLS_HDR_CHAT)
    # Changing someone else's nick/icon/status is a moderator action.
    if not user.hasPriv( PRIV_KICK_USERS ):
        chat.addString( DATA_STRING , "\rYou are not allowed to use /0wn." )
        server.sendPacket( user.uid , chat )
        return
    try:
        uid = int(arg.split()[0])
        var = arg.split()[1]
        val = arg.split()[2]
        if var in ( "color" , "icon" ):
            val = int( val ) & 0xFFFF
    except:
        chat.addString( DATA_STRING , "\rUsage: /0wn uid variable value (and not var=value)" )
        server.sendPacket( user.uid , chat )
        return

    tuser = server.getUser( uid )
    if ( tuser is None ) or ( not tuser.isLoggedIn() ) or ( not tuser.local ):
        chat.addString( DATA_STRING , "\rSorry, this user does not exists." )
        server.sendPacket( user.uid , chat )
        return
    if tuser.account.login != user.account.login and tuser.hasPriv( PRIV_KICK_PROTECT ):
        chat.addString( DATA_STRING , "\rSorry, %s cannot be 0wned." % tuser.nick )
        server.sendPacket( user.uid , chat )
        return

    chat.addString( DATA_STRING , "\r0wning %s, %s=%s" % (uid, var, val) )
    server.sendPacket( user.uid, chat )
    if ( var == "color" ):
        tuser.status = ( val & ~STATUS_ADMIN ) | ( tuser.status & STATUS_ADMIN )
    elif ( var == "name" ):
        tuser.nick = cleanNick( val )
    elif ( var == "icon" ):
        tuser.icon = val
    server.dispatchPacket( tuser.uid , HLPacket(HTLC_HDR_USER_CHANGE) )
