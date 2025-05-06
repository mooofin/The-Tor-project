import os
import re
import hashlib

"""Common utilities for GetTor modules."""

LOGGING_FORMAT = "[%(levelname)s] %(asctime)s; %(message)s"
DATE_FORMAT = "%Y-%m-%d"  # %H:%M:%S


windows_regex = re.compile(r'^torbrowser-install-\d+\.\d+(?:\.\d+)?_(\w{2})(?:-\w{2})?\.exe$')
linux_regex = re.compile(r'^tor-browser-linux(\d{2})-\d+\.\d+(?:\.\d+)?_(\w{2})(?:-\w{2})?\.tar\.xz$')
osx_regex = re.compile(r'^TorBrowser-\d+\.\d+(?:\.\d+)?-osx\d{2}_(\w{2})(?:-\w{2})?\.dmg$')


def get_logging_format():
    """Get the logging format.
    :return: (string) the logging format.
    """
    return LOGGING_FORMAT


def get_date_format():
    """Get the date format for logging.
    :return: (string) the date format for logging.
    """
    return DATE_FORMAT


def get_sha256(string):
    """Get sha256 of a string.
    :param: (string) the string to be hashed.
    :return: (string) the sha256 of string.
    """
    if not isinstance(string, (bytes, bytearray)):
        string = string.encode('utf-8')
    return hashlib.sha256(string).hexdigest()


def get_bundle_info(filename, osys=None):
    """Get the os, arch and lc from a bundle string.
    :param: filename (string) the name of the file.
    :param: osys (string) the OS.
    :raise: ValueError if the bundle doesn't have a valid bundle format.
    :return: (list) the os, arch and lc.
    """
    m_windows = windows_regex.search(filename)
    m_linux = linux_regex.search(filename)
    m_osx = osx_regex.search(filename)

    if m_windows:
        return 'windows', '32/64', m_windows.group(1)
    elif m_linux:
        return 'linux', m_linux.group(1), m_linux.group(2)
    elif m_osx:
        return 'osx', '64', m_osx.group(1)
    else:
        raise ValueError(f"Invalid bundle format: {filename}")


def valid_format(filename, osys=None):
    """Check for valid bundle format.
    :param: filename (string) the name of the file.
    :return: (boolean) true if the bundle format is valid, false otherwise.
    """
    return any([
        windows_regex.fullmatch(filename),
        linux_regex.fullmatch(filename),
        osx_regex.fullmatch(filename)
    ])


def get_file_sha256(file):
    """Get the sha256 of a file.
    :param: file (string) the path of the file.
    :return: (string) the sha256 hash.
    """
    BLOCKSIZE = 65536
    hasher = hashlib.sha256()

    try:
        with open(file, 'rb') as afile:
            for block in iter(lambda: afile.read(BLOCKSIZE), b''):
                hasher.update(block)
        return hasher.hexdigest()
    except FileNotFoundError:
        raise ValueError(f"File not found: {file}")
    except PermissionError:
        raise ValueError(f"Permission denied: {file}")
    except Exception as e:
        raise ValueError(f"Error hashing file {file}: {e}")


def find_files_to_upload(upload_dir):
    """
    Find the files which are named correctly and have a .asc file.
    :param: upload_dir (string) directory to search.
    :return: (list) list of files and their .asc files.
    """
    files = []

    if not os.path.isdir(upload_dir):
        raise ValueError(f"Upload directory not found: {upload_dir}")

    for name in os.listdir(upload_dir):
        full_path = os.path.join(upload_dir, name)
        asc_path = f"{full_path}.asc"

        if valid_format(name) and os.path.isfile(asc_path):
            files.append(name)
            files.append(f"{name}.asc")

    return files
