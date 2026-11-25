import os
import re
import subprocess

# Server-side scripts live here; only files directly inside it can run.
EXEC_DIR = os.path.join( os.path.dirname( os.path.dirname( os.path.abspath( __file__ ) ) ) , "support" , "exec" )
# Script names: letters, digits, "-" and "_" only, so a name can never
# point outside EXEC_DIR.
SCRIPT_NAME = re.compile( r'^[A-Za-z0-9_-]+$' )
EXEC_TIMEOUT = 5

def findScript( cmd ):
    """ Returns the path of the executable script named ``cmd`` in
    EXEC_DIR, or None if there is no such script. """
    if not SCRIPT_NAME.match( cmd or "" ):
        return None
    path = os.path.join( EXEC_DIR , cmd )
    if os.path.isfile( path ) and os.access( path , os.X_OK ):
        return path
    return None

def shell_exec( user , cmd , arg ):
    """ Runs the server-side script ``cmd`` from support/exec with ``arg``
    split into words as its arguments, and returns its output, or None if
    there is no such script or it failed.

    The script is run directly, never through a shell, so nothing in
    ``arg`` is interpreted. User details are passed in its environment. """
    path = findScript( cmd )
    if path is None:
        return None
    nick = user.nick
    if isinstance( nick , (bytes , bytearray) ):
        nick = nick.decode( 'mac-roman' )
    env = {
        "PATH": os.environ.get( "PATH" , "/usr/bin:/bin" ),
        "_LOGIN": user.account.login,
        "_UID": str( user.uid ),
        "_IP": user.ip,
        "_ICON": str( user.icon ),
        "_COLOR": str( user.status ),
        "_NICK": nick,
        "_NAME": user.account.name,
        "_PRIVS": str( user.account.privs ),
        "_FROOT": user.account.fileRoot,
        "_PROTO": "IRC" if user.isIRC else "Hotline",
    }
    # Environment values can't contain NUL bytes.
    env = { k: str( v ).replace( "\0" , "" ) for k , v in env.items() }
    try:
        proc = subprocess.run(
            [ path ] + ( arg or "" ).split(),
            cwd = os.path.dirname( EXEC_DIR ),
            env = env,
            stdin = subprocess.DEVNULL,
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE,
            timeout = EXEC_TIMEOUT,
        )
    except ( OSError , ValueError , subprocess.TimeoutExpired ):
        return None
    if proc.stderr or proc.returncode != 0:
        return None
    return proc.stdout.decode( 'utf-8' , errors = 'replace' )
