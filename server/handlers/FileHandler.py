from __future__ import absolute_import
from shared.HLProtocol import *
from shared.HLTypes import *
from config import *
from struct import pack
import os

def installHandler( server ):
    server.registerPacketHandler( FileHandler() )

def parseDir( dir ):
    parts = []
    if ( dir == None ) or ( len( dir ) < 5 ):
        return parts
    pos = 0
    count = unpack( "!H" , dir[pos:pos+2] )[0]
    pos += 3
    while ( pos < len( dir ) ) and ( count > 0 ):
        size = unpack( "!H" , dir[pos:pos+2] )[0]
        pos += 2
        # Wire data arrives as ``bytes``; decode so callers can join with
        # ``str`` paths (``os.sep.join`` rejects mixed bytes/str in Py3).
        part = dir[pos:pos+size]
        if isinstance( part , (bytes , bytearray) ):
            part = part.decode( 'mac-roman' )
        parts.append( part )
        pos += size + 1
        count -= 1
    return parts

def _checkName( part ):
    """ Raises HLException unless ``part`` is a single, ordinary file or
    folder name: one that can't climb out of, or skip past, its folder. """
    if ( part in ( "." , ".." ) ) or ( "/" in part ) or ( os.sep in part ):
        raise HLException( "Invalid file or folder name." )
    # Control characters (NUL, CR, LF, ...) have no place in a file name
    # and would let names forge lines in the server's logs.
    if CONTROL_CHARS.search( part ):
        raise HLException( "Invalid file or folder name." )

def relativeParts( dir , file = None ):
    """ Returns the validated path components (str) for a directory part
    list and an optional filename, ignoring empty parts. """
    parts = []
    for part in list( dir ) + ( [ file ] if file else [] ):
        if isinstance( part , (bytes , bytearray) ):
            part = part.decode( 'mac-roman' )
        if len( part ) == 0:
            continue
        _checkName( part )
        parts.append( part )
    return parts

def buildPath( root , dir , file = None ):
    """ Build a path from a root directory, an array of directory parts, and
    a filename. Raises HLException for any path that would leave ``root``. """
    parts = relativeParts( dir , file )
    path = os.sep.join( [ root ] + parts )
    rootAbs = os.path.abspath( root )
    pathAbs = os.path.abspath( path )
    if not isInside( pathAbs , rootAbs ):
        raise HLException( "Invalid file or folder name." )
    if not ALLOW_LINKS_OUTSIDE_FILE_ROOT:
        # Symbolic links (to folders or files) must not lead outside the
        # root either. realpath resolves every link along the path,
        # including in parts that don't exist yet (uploads, new folders).
        if not isInside( os.path.realpath( path ) , os.path.realpath( root ) ):
            raise HLException( "Invalid file or folder name." )
    return path

def isInside( path , root ):
    """ True if absolute ``path`` is ``root`` or inside it. """
    return ( path == root ) or path.startswith( root.rstrip( os.sep ) + os.sep )

def requireName( name ):
    """ Returns ``name``, or raises HLException if it is empty (which would
    make the operation apply to the containing folder itself). """
    if not name:
        raise HLException( "No file or folder name given." )
    return name

def checkDropBox( user , parts ):
    """ Users without PRIV_VIEW_DROPBOXES may upload into drop boxes but
    not see or fetch what is in them. """
    if isDropBox( parts ) and not user.hasPriv( PRIV_VIEW_DROPBOXES ):
        raise HLException( "You are not allowed to view drop boxes." )

def isDropBox( parts ):
    """ True if the path (relative to the file root) is in a drop box. """
    return any( "DROP BOX" in part.upper() for part in parts )

def getFileType( path ):
    if os.path.isdir( path ):
        return HLCharConst( "fldr" )
    elif path.endswith( ".hpf" ):
        return HLCharConst( "HTft" )
    else:
        return HLCharConst( "????" )

def getFileCreator( path ):
    if os.path.isdir( path ):
        return 0
    elif path.endswith( ".hpf" ):
        return HLCharConst( "HTLC" )
    else:
        return HLCharConst( "????" )

class FileHandler( HLPacketHandler ):
    def __init__( self ):
        HLPacketHandler.__init__( self )
        self.registerHandlerFunction( HTLC_HDR_FILE_LIST , self.handleFileList )
        self.registerHandlerFunction( HTLC_HDR_FILE_GET , self.handleFileDownload )
        self.registerHandlerFunction( HTLC_HDR_FILE_PUT , self.handleFileUpload )
        self.registerHandlerFunction( HTLC_HDR_FILE_DELETE , self.handleFileDelete )
        self.registerHandlerFunction( HTLC_HDR_FILE_MKDIR , self.handleFolderCreate )
        self.registerHandlerFunction( HTLC_HDR_FILE_MOVE , self.handleFileMove )
        self.registerHandlerFunction( HTLC_HDR_FILE_GETINFO , self.handleFileGetInfo )
        self.registerHandlerFunction( HTLC_HDR_FILE_SETINFO , self.handleFileSetInfo )
    
    def handleFileList( self , server , user , packet ):
        dir = parseDir( packet.getBinary( DATA_DIR ) )
        path = buildPath( user.account.fileRoot , dir )
        parts = relativeParts( dir )

        if not os.path.exists( path ):
            raise HLException("The specified directory does not exist.")
        if not os.path.isdir( path ):
            raise HLException("The specified path is not a directory.")
        if ( not user.hasPriv( PRIV_VIEW_DROPBOXES ) ) and isDropBox( parts ):
            raise HLException("You are not allowed to view drop boxes.")
        fn = parts[-1] if parts else "" # gets folder name kang
        #beware of non exact matches!! FIXME
        if isDropBox( parts ) and (fn.upper()[0:4] != "DROP") and (fn.upper().find(user.account.login.upper()) < 0):
            raise HLException("Sorry, this is not your dropbox. You are not allowed to view it")
        
        reply = HLPacket( HTLS_HDR_TASK , packet.seq )
        files = os.listdir( path )
        for fname in files:
            if SHOW_DOTFILES or ( fname[0] != '.' ):
                # Only list files starting with . if SHOW_DOTFILES is True.
                fpath = os.path.join( path , fname )
                type = getFileType( fpath )
                creator = getFileCreator( fpath )
                if os.path.isdir( fpath ):
                    size = len( os.listdir( fpath ) )
                else:
                    size = os.path.getsize( fpath )
                # ``os.listdir`` yields ``str`` in Py3; encode the name so
                # the trailing portion of the binary record is bytes.
                fname_bytes = fname.encode( 'mac-roman' ) if isinstance( fname , str ) else fname
                data = pack( "!5L" , type , creator , size , size , len( fname_bytes ) ) + fname_bytes
                reply.addBinary( DATA_FILE , data )
        server.sendPacket( user.uid , reply )
    
    def handleFileDownload( self , server , user , packet ):
        dir = parseDir( packet.getBinary( DATA_DIR ) )
        name = packet.getString( DATA_FILENAME , "" )
        resume = HLResumeData( packet.getBinary( DATA_RESUME ) )
        options = packet.getNumber( DATA_XFEROPTIONS , 0 )
        
        if not user.hasPriv( PRIV_DOWNLOAD_FILES ):
            raise HLException("You are not allowed to download files.")
        path = buildPath( user.account.fileRoot , dir , requireName( name ) )
        checkDropBox( user , relativeParts( dir ) )
        if not os.path.isfile( path ):
            raise HLException("Specified file does not exist.")
        
        offset = resume.forkOffset( HLCharConst( "DATA" ) )
        if ( offset < 0 ) or ( offset > os.path.getsize( path ) ):
            offset = 0
        xfer = server.fileserver.addDownload( user.uid , path , offset )
        
        reply = HLPacket( HTLS_HDR_TASK , packet.seq )
        # XFERSIZE/FILESIZE/XFERID are always 32-bit on the wire — using
        # the auto-sizing addNumber() truncates small values to 16 bits,
        # which the client rejects with "No reference number in reply".
        reply.addInt32( DATA_XFERSIZE , xfer.total )
        reply.addInt32( DATA_FILESIZE , xfer.dataSize )
        reply.addInt32( DATA_XFERID , xfer.id )
        server.sendPacket( user.uid , reply )

    def handleFileUpload( self , server , user , packet ):
        dir = parseDir( packet.getBinary( DATA_DIR ) )
        name = packet.getString( DATA_FILENAME , "" )
        size = packet.getNumber( DATA_XFERSIZE , 0 )
        options = packet.getNumber( DATA_XFEROPTIONS , 0 )
        
        if not user.hasPriv( PRIV_UPLOAD_FILES ):
            raise HLException("You are not allowed to upload files.")
        
        path = buildPath( user.account.fileRoot , dir , requireName( name ) )
        if os.path.exists( path ):
            # If this path exists, theres already a complete file.
            raise HLException("File already exists.")
        dirParts = relativeParts( dir )
        if ( not user.hasPriv( PRIV_UPLOAD_ANYWHERE ) ) and not any( "UPLOAD" in part.upper() for part in dirParts ):
            raise HLException("You must upload to an upload directory.")
        
        # Make sure we have enough disk space to accept the file. In Py3
        # ``os.statvfs`` returns a named tuple, not an indexable mapping —
        # the old ``F_BAVAIL`` / ``F_FRSIZE`` constants from the (removed)
        # ``statvfs`` module are gone. Use the named attributes instead.
        upDir = buildPath( user.account.fileRoot , dir )
        if not os.path.isdir( upDir ):
            raise HLException("The specified directory does not exist.")
        if not hasFreeSpace( upDir , size ):
            raise HLException("Insufficient disk space.")
        
        # All uploads in progress should have this extension.
        path += ".hpf"
        
        xfer = server.fileserver.addUpload( user.uid , path )
        if size > 0:
            xfer.total = size
        reply = HLPacket( HTLS_HDR_TASK , packet.seq )
        # XFERID must be 32-bit on the wire (see handleFileDownload).
        reply.addInt32( DATA_XFERID , xfer.id )
        if os.path.exists( path ):
            resume = HLResumeData()
            resume.setForkOffset( HLCharConst( "DATA" ) , os.path.getsize( path ) )
            reply.addBinary( DATA_RESUME , resume.flatten() )
        server.sendPacket( user.uid , reply )
    
    def handleFileDelete( self , server , user , packet ):
        dir = parseDir( packet.getBinary( DATA_DIR ) )
        name = packet.getString( DATA_FILENAME , "" )
        
        path = buildPath( user.account.fileRoot , dir , requireName( name ) )
        if not os.path.lexists( path ):
            raise HLException("Specified file does not exist.")
        isFolder = os.path.isdir( path ) and not os.path.islink( path )
        if isFolder and not user.hasPriv( PRIV_DELETE_FOLDERS ):
            raise HLException("You are not allowed to delete folders.")
        if ( not isFolder ) and not user.hasPriv( PRIV_DELETE_FILES ):
            raise HLException("You are not allowed to delete files.")
        
        if isFolder:
            # First, recursively delete everything inside the directory
            # (symbolic links are removed, never followed).
            for ( root , dirs , files ) in os.walk( path , topdown = False ):
                for name in files:
                    os.unlink( os.path.join( root , name ) )
                for name in dirs:
                    sub = os.path.join( root , name )
                    if os.path.islink( sub ):
                        os.unlink( sub )
                    else:
                        os.rmdir( sub )
            # Then delete the directory itself.
            os.rmdir( path )
        else:
            os.unlink( path )
        
        server.sendPacket( user.uid , HLPacket( HTLS_HDR_TASK , packet.seq ) )
    
    def handleFolderCreate( self , server , user , packet ):
        dir = parseDir( packet.getBinary( DATA_DIR ) )
        name = packet.getString( DATA_FILENAME , "" )
        
        if not user.hasPriv( PRIV_CREATE_FOLDERS ):
            raise HLException("You are not allowed to create folders.")
        path = buildPath( user.account.fileRoot , dir , requireName( name ) )
        if os.path.lexists( path ):
            raise HLException("Specified directory/file already exists.")
        
        os.mkdir( path , 0o755 )
        server.sendPacket( user.uid , HLPacket( HTLS_HDR_TASK , packet.seq ) )
    
    def handleFileMove( self , server , user , packet ):
        oldDir = parseDir( packet.getBinary( DATA_DIR ) )
        newDir = parseDir( packet.getBinary( DATA_NEWDIR ) )
        name = packet.getString( DATA_FILENAME , "" )
        
        oldPath = buildPath( user.account.fileRoot , oldDir , requireName( name ) )
        newPath = buildPath( user.account.fileRoot , newDir , name )
        
        if not os.path.lexists( oldPath ):
            raise HLException("Invalid file or directory.")
        if os.path.isdir( oldPath ):
            if not user.hasPriv( PRIV_MOVE_FOLDERS ):
                raise HLException("You are not allowed to move folders.")
            if os.path.abspath( newPath ).startswith( os.path.abspath( oldPath ) + os.sep ):
                raise HLException("A folder cannot be moved into itself.")
        elif not user.hasPriv( PRIV_MOVE_FILES ):
            raise HLException("You are not allowed to move files.")
        if os.path.lexists( newPath ):
            raise HLException("The specified file already exists.")
        
        os.rename( oldPath , newPath )
        server.sendPacket( user.uid , HLPacket( HTLS_HDR_TASK , packet.seq ) )
    
    def handleFileGetInfo( self , server , user , packet ):
        dir = parseDir( packet.getBinary( DATA_DIR ) )
        name = packet.getString( DATA_FILENAME , "" )
        
        path = buildPath( user.account.fileRoot , dir , requireName( name ) )
        checkDropBox( user , relativeParts( dir ) )
        if not os.path.exists( path ):
            raise HLException("No such file or directory.")
        
        info = HLPacket( HTLS_HDR_TASK , packet.seq )
        info.addString( DATA_FILENAME , name )
        # FILESIZE/FILETYPE/FILECREATOR are 32-bit on the wire; addNumber's
        # auto-sizing would shrink small values (or 0 for folders) to 16 bits.
        info.addInt32( DATA_FILESIZE , os.path.getsize( path ) & 0xFFFFFFFF )
        info.addInt32( DATA_FILETYPE , getFileType( path ) )
        info.addInt32( DATA_FILECREATOR , getFileCreator( path ) )
        server.sendPacket( user.uid , info )
    
    def handleFileSetInfo( self , server , user , packet ):
        dir = parseDir( packet.getBinary( DATA_DIR ) )
        oldName = packet.getString( DATA_FILENAME , "" )
        newName = packet.getString( DATA_NEWFILE , oldName )
        
        oldPath = buildPath( user.account.fileRoot , dir , requireName( oldName ) )
        newPath = buildPath( user.account.fileRoot , dir , requireName( newName ) )
        
        if not os.path.lexists( oldPath ):
            raise HLException("Invalid file or directory.")
        if oldName != newName:
            if os.path.isdir( oldPath ):
                if not user.hasPriv( PRIV_RENAME_FOLDERS ):
                    raise HLException("You cannot rename folders.")
            elif not user.hasPriv( PRIV_RENAME_FILES ):
                raise HLException("You cannot rename files.")
        if os.path.lexists( newPath ):
            raise HLException("The specified file already exists.")
        
        os.rename( oldPath , newPath )
        server.sendPacket( user.uid , HLPacket( HTLS_HDR_TASK , packet.seq ) )
