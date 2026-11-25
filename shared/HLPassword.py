""" Password hashing for accounts.

Passwords used to be stored as unsalted MD5 hashes, which are cracked in
moments if the accounts file or table leaks. They are now stored salted
and stretched with PBKDF2-HMAC-SHA256, as

    $p1$<salt>$<hash>

(base64url without padding: 4 + 16 + 1 + 43 = 64 characters, the size of
the MySQL password column). "p1" stands for these parameters; a future
change of parameters would use a new tag. Old MD5 hashes are still
accepted, and replaced on the account's next successful login.

The iteration count is moderate on purpose: phxd verifies passwords on
its single thread, so a very slow hash would let anyone stall the server
by logging in repeatedly.
"""
from __future__ import absolute_import

import base64
import hashlib
import hmac
import os
import re

PREFIX = "$p1$"
ITERATIONS = 20000
SALT_BYTES = 12
LEGACY_MD5 = re.compile( r'^[0-9a-f]{32}$' )


def _b64( data ):
    return base64.urlsafe_b64encode( data ).rstrip( b"=" ).decode( "ascii" )


def _unb64( text ):
    return base64.urlsafe_b64decode( text + "=" * ( -len( text ) % 4 ) )


def _bytes( password ):
    if password is None:
        return b""
    if isinstance( password , str ):
        return password.encode( "mac-roman" , errors = "replace" )
    return bytes( password )


def hashPassword( password ):
    """ Returns the string to store for ``password`` (str or bytes). """
    salt = os.urandom( SALT_BYTES )
    digest = hashlib.pbkdf2_hmac( "sha256" , _bytes( password ) , salt , ITERATIONS )
    return PREFIX + _b64( salt ) + "$" + _b64( digest )


def verifyPassword( stored , password ):
    """ True if ``password`` matches the stored hash (current or legacy
    MD5 format). Comparisons take the same time whatever matches. """
    stored = stored or ""
    password = _bytes( password )
    if stored.startswith( PREFIX ):
        try:
            salt , digest = stored[len( PREFIX ):].split( "$" , 1 )
            expected = _unb64( digest )
            actual = hashlib.pbkdf2_hmac( "sha256" , password , _unb64( salt ) , ITERATIONS )
        except ( ValueError , TypeError ):
            return False
        return hmac.compare_digest( actual , expected )
    if LEGACY_MD5.match( stored ):
        return hmac.compare_digest( hashlib.md5( password ).hexdigest() , stored )
    return False


def needsUpgrade( stored ):
    """ True if ``stored`` is in an old format that should be replaced. """
    return not ( stored or "" ).startswith( PREFIX )
