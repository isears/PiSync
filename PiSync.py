import paramiko, stat, os, datetime, copy, hashlib, time, shutil, errno, tempfile, sys, configparser, tkinter

# Some global vars
CONFIG_BASE_DIR = os.path.join(os.path.expanduser('~'), ".PiSync")
LAST_CHECK_FILE = os.path.join(CONFIG_BASE_DIR, "lastCheck.txt")
INI_FILE = os.path.join(CONFIG_BASE_DIR, "pisync.ini")
LOG_FILE = os.path.join(CONFIG_BASE_DIR, "log.txt")
HOST = ""
UNAME = ""
PASSWORD = ""
AUTH_TYPE = ""
KEY_FILE = ""
LOCAL_BASE_DIR = ""
REMOTE_BASE_DIR = ""
PORT = 22
RECONNECTION_TIME_SECONDS = 10
THROTTLING = 0
LOG_FILE_IDX = 0
LOG_FILE_MAX_LEN = 0


def log_msg(msg):
    """
    Writes input to logfile with path specified by LOG_FILE.
    If the log file grows over LOG_FILE_MAX_LEN, its contents are emptied.

    :param msg: The string to write to the file
    :return: None
    """
    global LOG_FILE_IDX
    LOG_FILE_IDX += 1
    if LOG_FILE_IDX > LOG_FILE_MAX_LEN: # Erase logfile if it gets too large
        open(LOG_FILE, 'w').close()

    log_str = ""
    log_str += "[" + datetime.datetime.now().isoformat() + "]"
    log_str += " "
    log_str += msg

    fp = open(LOG_FILE, 'a')
    print(log_str, file=fp)




def hardExitHandler(msg):
    """
    An alias for sys.exit(). Writes a message to the log before exiting

    :param msg: The string to be written to the log (gives reason for shutdown)
    :return: None
    """
    log_msg("WARNING: PiSync process ending for the following reason: " + msg)
    sys.exit(0)


def getPass():
    """
    Creates a simple tkinter dialog that prompts the user for a password to the SFTP server

    :return: a string representing the password
    """
    root = tkinter.Tk()
    root.title("PiSync")
    password_var = tkinter.StringVar()

    tkinter.Label(root, text="Enter password for key file or SSH user:", width=50).grid(row=0)
    tkinter.Entry(root, width=20, textvariable=password_var, show="*").grid(row=1)
    tkinter.Button(root, text="Enter", command=root.destroy).grid(row=2, sticky=tkinter.W)

    root.bind("<Return>", lambda event: root.destroy())
    root.protocol("WM_DELETE_WINDOW", lambda: hardExitHandler("AUTH failure"))
    root.wm_attributes("-topmost", 1)
    root.mainloop()

    return password_var.get()


def init_config():
    """
    Fills all the global configuration variables by reading the config file whose path is given by INI_FILE:
    HOST, PORT, UNAME, AUTH_TYPE, PASSWORD, KEY_FILE, LOCAL_BASE_DIR, THROTTLING, LOG_FILE_MAX_LEN, REMOTE_BASE_DIR

    :return: None
    """
    if not os.path.isdir(CONFIG_BASE_DIR):
        log_msg("ERROR: Could not find local configurations. Check that CONFIG_BASE_DIR is set correctly.")
        hardExitHandler("configuration error")

    if not os.path.exists(INI_FILE):
        log_msg("ERROR: No ini file. Check that INI_FILE is set correctly.")
        hardExitHandler("configuration error")

    global HOST, PORT, UNAME, AUTH_TYPE, PASSWORD, KEY_FILE, LOCAL_BASE_DIR, THROTTLING, LOG_FILE_MAX_LEN, REMOTE_BASE_DIR

    try:
        config = configparser.ConfigParser()
        config.read(INI_FILE)

        HOST = config['HOST']['host']
        PORT = int(config['HOST']['port'])
        AUTH_TYPE = config['AUTH']['auth']
        UNAME = config['AUTH']['user']
        KEY_FILE = config['AUTH']['keyfile']
        LOCAL_BASE_DIR = config['LOCAL CONFIG']['local_base']
        THROTTLING = int(config['LOCAL CONFIG']['throttling'])
        LOG_FILE_MAX_LEN = int(config['LOCAL CONFIG']['log_file_max'])
        REMOTE_BASE_DIR = config['REMOTE CONFIG']['remote_base']

    except KeyError as e:
        log_msg("ERROR: ini file misconfigured. Bad param: " + str(e))
        hardExitHandler("configuration error")

    PASSWORD = getPass()



def setupConnection():
    """
    Sets up SFTP connection. Authenticates with public key or password based on options specified in config file.
    Note: To avoid storing passwords in any config files, user will be prompted to enter password at runtime.

    :return: None
    """
    transport = paramiko.Transport((HOST, PORT))

    if AUTH_TYPE == "publickey":
        p_key = paramiko.RSAKey.from_private_key_file(KEY_FILE, password=PASSWORD)
        transport.connect(username=UNAME, pkey=p_key)

    elif AUTH_TYPE == "password":
        transport.connect(username=UNAME, password=PASSWORD)

    else:
        log_msg("ERROR: ini file misconfigured. Unrecognized authtype.")
        hardExitHandler("configuration error")

    sftp_conn = paramiko.SFTPClient.from_transport(transport)

    return sftp_conn



def getRemoteListing(sftp_conn, path, root_path, file_list):
    """
    Recursively gets directory tree of file system on server.

    :param sftp_conn: paramiko SFTPClient object with a valid server connection
    :param path: the path to expand
    :param root_path: recursive structure means every call must have a ref to the root path to build absolute paths
    :param file_list: a pointer to a list of file objects that is built incrementally
    :return: None
    """
    listing = sftp_conn.listdir_attr(path)

    for file_obj in listing:
        if path + "/" + file_obj.filename not in [ x['fullPath'] for x in file_list]:
            if not stat.S_ISLNK(file_obj.st_mode): # No symlinks in virtual file system (this can be unsafe)
                modify_time = datetime.datetime.fromtimestamp(file_obj.st_mtime)
                # file_info is a dictionary with name, time, and children attributes. If file not dir, children is empty
                file_info = {
                    "fullPath": path + "/" + file_obj.filename,
                    "sharePath": path.replace(root_path, "", 1) + "/" + file_obj.filename,
                    "time": modify_time,
                    "isDir": stat.S_ISDIR(file_obj.st_mode)
                }

                if stat.S_ISDIR(file_obj.st_mode):
                    file_info["time"] = True # Hack-y method of preventing timestamp analysis
                    getRemoteListing(sftp_conn, path + "/" + file_obj.filename, root_path, file_list)

                file_list.append(file_info)



def getLocalListing(path, root_path, file_list):
    """
    Recursively gets directory tree of local file system

    :param path: the path to expand
    :param root_path: recursive structure means every call must have a ref to the root path to build absolute paths
    :param file_list: a pointer to a list of file objects that is built incrementally
    :return: None
    """
    listing = os.listdir(path)

    for name in listing:
        if path + "/" + name not in [ x['fullPath'] for x in file_list]:
            if not os.path.islink(path + "/" + name): # No symlinks in the virtual file system (this can be unsafe)
                modify_time = datetime.datetime.fromtimestamp(os.stat(path + "/" + name).st_mtime)
                file_info = {
                    "fullPath" : path + "/" + name,
                    "sharePath" : path.replace(root_path, "", 1) + "/" + name,
                    "time" : modify_time,
                    "isDir" : os.path.isdir(path + "/" + name)
                }

                if os.path.isdir(path + "/" + name):
                    file_info["time"] = True
                    getLocalListing(path + "/" + name, root_path, file_list)

                file_list.append(file_info)



def local_md5(path):
    """
    Calculates md5 checksum of local file.
    Thanks to QuantumSoup from Stack Overflow:
    http://stackoverflow.com/questions/3431825/generating-an-md5-checksum-of-a-file

    :param path: local path to file
    :return: None
    """
    max_read = 4096
    hashMD5 = hashlib.md5()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(max_read), b""):
            hashMD5.update(chunk)

    return hashMD5.hexdigest()


def remote_md5(full_path, sftp_conn):
    """
    Calculates md5 checksum of remote by downloading to a temp file and then calculating md5 locally. Unfortunately
    most SFTP servers do not offer checksum functions.

    :param full_path: remote path to file
    :param sftp_conn: paramiko sftp object with valid connection
    :return: None
    """
    fd, tmp_filename = tempfile.mkstemp()
    sftp_conn.get(full_path, tmp_filename)
    ret = local_md5(tmp_filename)
    os.close(fd)
    os.remove(tmp_filename)
    return ret


def checksum_validates(share_path, sftp_conn):
    """
    Compares checksums of remote and local files to determine if they are the same.

    :param share_path: a path that refers to the file's location within virtual file system (same for local and remote)
    :param sftp_conn: paramiko sftp object with valid connection
    :return: bool -> true if checksums are the same, false otherwise
    """
    return local_md5(LOCAL_BASE_DIR + "/" + share_path) == remote_md5(REMOTE_BASE_DIR + "/" + share_path, sftp_conn)


def getFileBySharePath(file_obj_list, shareFileName):
    """
    Finds a file object in the list that has a sharePath attribute corresponding to shareFileName

    :param file_obj_list: a list of file objects (i.e. as returned from getLocalListing or getRemoteListing)
    :param shareFileName: the share path to find
    :return: False if no file can be found, the file object itself if it can be found
    """
    for file_obj in file_obj_list:
        if file_obj['sharePath'] == shareFileName:
            ret = file_obj
            break
    else:
        ret = False

    return ret


def getUniqueFiles(file_obj_lists):
    """
    Builds a list of share paths corresponding the file objects that exist on both sides of the connection.

    :param file_obj_lists: a list of file objects (i.e. as returned from getLocalListing or getRemoteListing funcs)
    :return: None
    """
    unique_share_paths = list()

    for file_obj_list in file_obj_lists:
        for file_obj in file_obj_list:
            if not file_obj['sharePath'] in unique_share_paths:
                unique_share_paths.append(file_obj['sharePath'])

    return unique_share_paths


def getSimilarFiles(l_files, r_files, directories=False):
    """
    Compares two lists of file objects and returns a list containing all the share paths corresponding to file objects
    that appear in both lists.
    Note: directories are not included in the return list because this breaks the first_cycle_run function.

    :param l_files: list of local file objects
    :param r_files: list of remote file objects
    :param directories: specifies whether or not directories should be considered
    :return: a list of share paths corresponding to file objects that appear in both lists
    """
    similar_share_paths = list()

    for l_file_obj in l_files:
        for r_file_obj in r_files:
            if l_file_obj['sharePath'] == r_file_obj['sharePath']:
                if not directories and l_file_obj['isDir']:
                    pass
                else:
                    similar_share_paths.append(l_file_obj['sharePath'])

    return similar_share_paths


def remoteDirDelete(full_path, sftp_conn):
    """
    Recursively deletes a remote directory tree.

    :param full_path: full path to the directory
    :param sftp_conn: paramiko SFTP object with a valid connection
    :return: None
    """
    for file_obj in sftp_conn.listdir_attr(full_path):
        if stat.S_ISDIR(file_obj.st_mode):
            remoteDirDelete(full_path + "/" + file_obj.filename, sftp_conn)
        else:
            sftp_conn.remove(full_path + "/" + file_obj.filename)

    sftp_conn.rmdir(full_path)


def handleRemoteDelete(share_path):
    """
    Handler for a remote delete event. Removes the corresponding local file.
    Note: When a directory is deleted, the entire sub-tree will be deleted. Therefore, the function may be called to
    delete files that have already been deleted by a previous directory-tree delete. This means the function may attempt
    to delete non-existent files, necessitating a try/catch clause.

    :param share_path: the share path of the file that was deleted
    :return: None
    """
    log_msg("Remote delete detected - removing local file: " + share_path)
    if os.path.isdir(LOCAL_BASE_DIR + "/" + share_path):
        shutil.rmtree(LOCAL_BASE_DIR + "/" + share_path)
    else:
        # Need try/catch here because if entire directory was already deleted file will not exist
        try:
            os.remove(LOCAL_BASE_DIR + "/" + share_path)
        except FileNotFoundError:
            pass


def handleRemoteAdd(share_path, sftp_conn):
    """
    Handler for remote add event. Download file and adds to local file system.

    :param share_path: share path of the file added
    :param sftp_conn: paramiko SFTP object with valid connection
    :return: None
    """
    log_msg("Remote add detected - adding/modifying local file: " + share_path)

    if stat.S_ISDIR(sftp_conn.stat(REMOTE_BASE_DIR + "/" + share_path).st_mode):
        os.mkdir(LOCAL_BASE_DIR + "/" + share_path)
    else:
        sftp_conn.get(REMOTE_BASE_DIR + "/" + share_path, LOCAL_BASE_DIR + "/" + share_path)


def handleLocalDelete(share_path, sftp_conn):
    """
    Handler for local delete event. Removes the corresponding remote file
    Note: When a directory is deleted, the entire sub-tree will be deleted. Therefore, the function may be called to
    delete files that have already been deleted by a previous directory-tree delete. This means the function may attempt
    to delete non-existent files, necessitating a try/catch clause.

    :param share_path: share path to file in question
    :param sftp_conn: paramiko SFTP object with valid connection
    :return: None
    """
    log_msg("Local delete detected - removing remote file: " + share_path)

    if stat.S_ISDIR(sftp_conn.stat(REMOTE_BASE_DIR + "/" + share_path).st_mode):
        remoteDirDelete(REMOTE_BASE_DIR + "/" + share_path, sftp_conn)
    else:
        # Need try/catch here because if entire directory was already deleted file will not exist
        try:
            sftp_conn.remove(REMOTE_BASE_DIR + "/" + share_path)
        except FileNotFoundError:
            pass


def handleLocalAdd(share_path, sftp_conn):
    """
    Handler for local add event. Upload file and add to remote file system.

    :param share_path: share path to the file in question
    :param sftp_conn: paramiko SFTP object with valid connection
    :return: None
    """
    log_msg("Local add detected - adding/modifying remote file: " + share_path)
    if os.path.isdir(LOCAL_BASE_DIR + share_path):
        sftp_conn.mkdir(REMOTE_BASE_DIR + "/" + share_path)
    else:
        sftp_conn.put(LOCAL_BASE_DIR + "/" + share_path, REMOTE_BASE_DIR + "/" + share_path)


def first_cycle_run(sftp_conn):
    """
    Performs all necessary actions on the first cycle:
    - Gets remote and local file system states
    - Determines what changes happened since last contact with the server
    - Takes appropriate action for each change

    Note: this function does not handle add/delete cases because the main cycle should be able to handle those
    regardless of a loss of connection with the server.

    :param sftp_conn:
    :return:
    """
    log_msg("Connection Established! Searching for file system changes since last communication with server...")

    r_files_initial = list()
    l_files_initial = list()

    getRemoteListing(sftp_conn, REMOTE_BASE_DIR, REMOTE_BASE_DIR, r_files_initial)
    getLocalListing(LOCAL_BASE_DIR, LOCAL_BASE_DIR, l_files_initial)

    if os.path.isfile(LAST_CHECK_FILE):
        with open(LAST_CHECK_FILE, "r") as f:
            last_sync_time = datetime.datetime.fromtimestamp(float(f.readline()))
    else:
        last_sync_time = datetime.datetime.fromtimestamp(0)

    similar_files = getSimilarFiles(l_files_initial, r_files_initial)

    for share_path in similar_files:
        local_file_obj = getFileBySharePath(l_files_initial, share_path)
        remote_file_obj = getFileBySharePath(r_files_initial, share_path)

        # Only local file was modified since last connection to server
        if local_file_obj["time"] > last_sync_time and remote_file_obj["time"] < last_sync_time:
            handleLocalAdd(share_path, sftp_conn)
        # Only remote file was modified since last connection to server
        elif local_file_obj["time"] < last_sync_time and remote_file_obj["time"] > last_sync_time:
            handleRemoteAdd(share_path, sftp_conn)
        # Both files modified since last connection to server: this is the hard case
        elif local_file_obj["time"] > last_sync_time and remote_file_obj["time"] > last_sync_time:
            # Problematic case: simple solution - just get most up-to-date data
            log_msg("WARNING: Remote & local changes detected since last communication with server - saving most recent")
            if local_file_obj["time"] > remote_file_obj["time"]:
                handleLocalAdd(share_path, sftp_conn)
            else:
                handleRemoteAdd(share_path, sftp_conn)

    log_msg("Initialization complete.")


def run():
    """
    The main finite state machine function. See readme for in-depth explanation.
    This function gets the current directory tree listings of the local and remote file system, and also uses the saved
    directory trees of local and remote file systems from the last cycle to determine the state of each file object.

    State is determined by the following 4 binary variables (for a total of 16 states):
    rfp: whether or not file is present in previous cycle's remote directory tree
    rfc: whether or not file is present in current cycle's remote directory tree
    lfp: whether or not file is present in previous cycle's local directory tree
    lfc: whether or not file is present in current cycle's local directory tree

    See comments below to read detailed information about each state.
    Note: state variables only determine if a file EXISTS. Timestamps must be used to determine if a file has been
    MODIFIED since last cycle within certain states.

    :return: None
    """
    conn = setupConnection()
    first_cycle_run(conn)

    r_files_prev = list()
    l_files_prev = list()

    r_files_curr = list()
    l_files_curr = list()

    getRemoteListing(conn, REMOTE_BASE_DIR, REMOTE_BASE_DIR, r_files_prev)
    getLocalListing(LOCAL_BASE_DIR, LOCAL_BASE_DIR, l_files_prev)


    while True:
        getRemoteListing(conn, REMOTE_BASE_DIR, REMOTE_BASE_DIR, r_files_curr)
        getLocalListing(LOCAL_BASE_DIR, LOCAL_BASE_DIR, l_files_curr)

        unique_files = getUniqueFiles([r_files_prev, r_files_curr, l_files_prev, l_files_curr])
        unique_files_sorted = sorted(unique_files, key = lambda x : len(x))

        for share_path in unique_files_sorted:
            rfp = getFileBySharePath(r_files_prev, share_path)
            rfc = getFileBySharePath(r_files_curr, share_path)
            lfp = getFileBySharePath(l_files_prev, share_path)
            lfc = getFileBySharePath(l_files_curr, share_path)

            if rfp and rfc and lfp and lfc:
                if rfp['time'] == rfc['time'] and lfp['time'] == lfc['time']: # Local and remote files unmodified
                    pass
                # Checksums have to be used in these next two conditions in order to prevent endless modify loops
                elif rfp['time'] == rfc['time'] and not lfp['time'] == lfc['time']: # Local file modified
                    if not checksum_validates(share_path, conn):
                        handleLocalAdd(share_path, conn)
                elif not rfp['time'] == rfc['time'] and lfp['time'] == lfc['time']: # Remote file modified
                    if not checksum_validates(share_path, conn):
                        handleRemoteAdd(share_path, conn)
                elif not rfp['time'] == rfc['time'] and not lfp['time'] == lfc['time']: # Simultaneous local and remote
                    # This case is problematic: simple solution - just take most up-to-date file
                    log_msg("WARNING: Simultaneous modifications on file system object. Using most up-to-date data.")
                    if rfc['time'] > lfc['time']:
                        handleRemoteAdd(share_path, conn)
                    else:
                        handleLocalAdd(share_path, conn)

            elif rfp and not rfc and lfp and lfc:
                if lfp['time'] == lfc['time']: # Remote file deleted
                    handleRemoteDelete(share_path)
                elif not lfp['time'] == lfc['time']: # Remote delete simultaneous with local modification
                    # This case is problematic: safe approach - upload local file instead of deleting
                    log_msg("WARNING: Local modifications simultaneous with remote delete. Playing it safe...")
                    handleLocalAdd(share_path, conn)

            elif not rfp and rfc and lfp and lfc:
                if lfp['time'] == lfc['time']: # Previous cycle PUSH succeeded
                    pass
                elif not lfp['time'] == lfc['time']: # Previous cycle PUSH succeeded and local file modified
                    handleLocalAdd(share_path, conn)

            elif not rfp and not rfc and lfp and lfc:
                log_msg("WARNING: PUSH fail detected for file: " + lfc['sharePath'])
                if lfp['time'] == lfc['time']: # Pervious cycle PUSH failed
                    handleLocalAdd(share_path, conn)
                elif not lfp['time'] == lfc['time']: # Previous cycle PUSH failed and local file modified
                    handleLocalAdd(share_path, conn)

            elif rfp and rfc and lfp and not lfc:
                if rfp['time'] == rfc['time']: # Local file deleted
                    handleLocalDelete(share_path, conn)
                elif not rfp['time'] == rfc['time']: # Local file deleted simultaneous with remote modifications
                    # This case is problematic: safe approach - download modified remote file instead of deleting
                    log_msg("WARNING: Remote modifications simultaneous with local delete. Playing it safe...")
                    handleRemoteAdd(share_path, conn)

            elif rfp and not rfc and lfp and not lfc: # Simultaneous local and remote deletes - nothing to do
                pass

            elif not rfp and rfc and lfp and not lfc: # Last cycle PUSH succeeded, but local file deleted
                handleLocalDelete(share_path, conn)

            elif not rfp and not rfc and lfp and not lfc: # Last cycle remote delete, local delete succeeded
                pass

            elif rfp and rfc and not lfp and lfc:
                if rfp['time'] == rfp['time']: # Last cycle PULL successful
                    pass
                elif not rfp['time'] == rfp['time']: # Last cycle PULL successful, but remote simultaneously modified
                    handleRemoteAdd(share_path, conn)

            elif rfp and not rfc and not lfp and lfc: # Last cycle PULL success, but remote simultaneously deleted
                handleRemoteDelete(share_path)

            elif not rfp and rfc and not lfp and lfc: # Simultaneous local and remote file creation/modification
                # This case is problematic. Simple solution: just take the most up-to-date file
                log_msg("WARNING: Simultaneous modifications on a new file system object. Using most up-to-date data.")
                if rfc['time'] > lfc['time']:
                    handleRemoteAdd(share_path, conn)
                else:
                    handleLocalAdd(share_path, conn)

            elif not rfp and not rfc and not lfp and lfc: # Local file created
                handleLocalAdd(share_path, conn)

            elif rfp and rfc and not lfp and not lfc: # Last cycle PULL failed
                log_msg("WARNING: PULL fail detected for file: " + rfc['sharePath'])
                if rfp['time'] == rfc['time']:
                    handleRemoteAdd(share_path, conn)
                if not rfp['time'] == rfc['time']: # Last cycle PULL fail and remote file simultaneously modified
                    handleRemoteAdd(share_path, conn)

            elif rfp and not rfc and not lfp and not lfc: # Last cycle local delete propogated correctly
                pass

            elif not rfp and rfc and not lfp and not lfc: # Remote file created
                handleRemoteAdd(share_path, conn)

            elif not rfp and not rfc and not lfp and not lfc: # Null case - only present for sake of completeness
                pass

        # Cleanup ops
        with open(LAST_CHECK_FILE, 'w') as f:
            f.write(str(time.time()))

        r_files_prev = copy.deepcopy(r_files_curr)
        l_files_prev = copy.deepcopy(l_files_curr)

        r_files_curr = list()
        l_files_curr = list()

        time.sleep(THROTTLING)


def main():
    """
    Main loop. Catches network connectivity and auth exceptions. Continuously attempts to reconnect to server after
    exception events.

    TODO: More exception cases should be added to make the process more robust.

    :return: None
    """
    while True:
        init_config()

        try:
            run()
        except ValueError as e:
            if "Could not unserialize key data" in str(e):
                log_msg("ERROR: could not unserialize key data")
            else:
                raise
        except paramiko.AuthenticationException:
            log_msg("ERROR: Auth failed.")
        except paramiko.SSHException:
            log_msg("ERROR: lost connection. Retrying in " + str(RECONNECTION_TIME_SECONDS) + " seconds.")
            time.sleep(RECONNECTION_TIME_SECONDS)


if __name__ == "__main__":
    main()