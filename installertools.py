import ctypes
import logging
import sys
import os
import re
import ssl
import shutil
import time
import platform
import tempfile
import threading
import winreg
from glob import glob
from os import rename, remove, chdir
from os.path import join, exists
from typing import Sequence
from urllib.request import urlretrieve
from zipfile import ZipFile

import sarge

__initial_indent = re.compile(r'^\s+', re.MULTILINE)
__whitespace_pattern = re.compile(r'\s+', re.MULTILINE)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def read_reg_key(root, key, value):
    key_handle = winreg.OpenKey(root, key)
    current_version, _ = winreg.QueryValueEx(value, "")
    winreg.CloseKey(key_handle)
    return current_version


def inspect_platform():
    system_info = platform.system()
    release_info = platform.release()
    logger.debug(f"System: {system_info} Release: {release_info}")


def current_directory():
    return os.path.dirname(os.path.realpath(__file__))


def copy_files(src, dest, override=False):
    logger.debug(f"Copying {src} to {dest}..")
    for file in glob(src):
        target = os.path.join(dest, os.path.basename(file))
        if override or not os.path.exists(target):
            copy_file(file, target)


def copy_file(src, dest):
    logger.debug(f"Copying file {src} to {dest}..")
    return shutil.copyfile(src, dest)


def get_desktop_path():
    return os.path.join(os.environ["HOMEPATH"], "Desktop")


def fix_pyinstaller_root():
    if hasattr(sys, '_MEIPASS'):
        chdir(sys._MEIPASS)


def write_temp_file(prefix, suffix, content):
    _, f = tempfile.mkstemp(suffix=suffix, prefix=prefix, text=True)
    write_file(f, content)
    return f


def write_file(filename, content):
    f = open(filename, '+w')
    f.write(content)
    f.close()


def run(cmd, canceller=None):
    cancelled = False
    finished = False

    logger.debug("Process executed: %s", cmd)
    pipeline = sarge.run(cmd, async=True)

    def kill_all_if_cancelled():
        while not finished:
            if canceller is not None and canceller():
                nonlocal cancelled
                cancelled = True
                for c in pipeline.commands:
                    c.terminate()
            time.sleep(0.5)

    watchdog = threading.Thread(target=kill_all_if_cancelled, name='process-watchdog', daemon=True)
    watchdog.start()

    pipeline.wait()
    finished = True
    if cancelled:
        raise InterruptedError()

    return pipeline.returncode


def timeout_canceller(timeout: int, canceller=None):
    start = time.time()

    def tick():
        return (time.time() - start >= timeout) or (canceller is not None and canceller())
    return tick


def download(url, filename, is_cancelled=None):
    def hook(block_num, block_size, total_size):
        global logger
        if is_cancelled is not None and is_cancelled():
            raise InterruptedError('Cancelled')
        percent = min(100 * block_num * block_size / total_size, 100.00)
        logger.debug("PROGRESS: %%%d", percent)

    if not exists(filename):
        if (not os.environ.get('PYTHONHTTPSVERIFY', '') and
                getattr(ssl, '_create_unverified_context', None)):
            ssl._create_default_https_context = ssl._create_unverified_context
        logger.debug("Downloading file %s from %s", filename, url)
        urlretrieve(url, filename=f'{filename}.part', reporthook=hook)
        rename(f'{filename}.part', filename)
        logger.debug("Successfully downloaded file %s ", filename)
    else:
        logger.debug("File %s was already in cache, skipped download. ", filename)


def extract(zipfile, destination_dict):
    z = ZipFile(zipfile)
    logger.debug("Cherry-picked extracting zip file %s", zipfile)
    for key, value in destination_dict.items():
        z.extract(key, value)
        logger.debug("File %s extracted to %s", key, value)
    z.close()


def extract_all(zipfile, destination_dir):
    z = ZipFile(zipfile)
    z.extractall(destination_dir)
    z.close()


def is_root():
    try:
        is_root_result = os.getuid() == 0
        logger.debug("Checking if user is root.. %b", is_root_result)
        return is_root_result
    except AttributeError:
        is_root_result = ctypes.windll.shell32.IsUserAnAdmin() != 0
        logger.debug("Checking if user is admin.. %s", 'OK' if is_root_result else 'ERROR!')
        return is_root_result


def windows_correct_icon():
    myappid = 'mycompany.myproduct.subproduct.version'
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)


def windows_run_as_admin():
    def run():
        params = ' '.join(sys.argv)
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    runner = threading.Thread(target=run, name='process-watchdog', daemon=False)
    runner.start()
    time.sleep(3)


def remove_all_files(path):
    for file in glob(join(path, '*')):
        remove(file)
        logger.debug("Removed file %s", file)


def get_interfaces_info():
    logger.debug("Fetching interface information..")
    interfaces = sarge.capture_stdout('netsh interface show interface')
    logger.debug("Invoking netsh to get interfaces information: " + str(interfaces.stdout.text).replace("\r", "").replace("\n", "\\n"))
    interfaces_output = str(interfaces.stdout.text).split("\r\n")[1:-2]
    field_indices = [match.start() for match in re.finditer(r'(\S+\s?)+', interfaces_output[0])]

    # TODO: select internet connection if more than one
    def extract_columns(line: str, start_indices: Sequence[int]):
        index_ranges = [(item, field_indices[idx + 1] if idx < len(field_indices) - 1 else len(line)) for idx, item in enumerate(start_indices)]
        return [line[start:end].strip() for start, end in index_ranges]

    interfaces_info = [extract_columns(interface, field_indices) for interface in interfaces_output[2:]]
    logger.debug("Retrieved interfaces information: " + str(interfaces_info))
    return interfaces_info


def args(string: str):
    return re.sub(__initial_indent, "", re.sub(__whitespace_pattern, " ", string))
