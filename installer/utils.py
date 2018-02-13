import os

import json
import traceback
from enum import Enum
from OpenSSL.crypto import load_certificate, FILETYPE_PEM
import win32serviceutil
import win32service
import requests
import urllib3
import winshell
import pythoncom
import fnmatch
import ctypes
import logging
import sys
import re
import shutil
import time
import platform
import tempfile
import threading
from urllib.parse import urlparse, urlunparse
from sarge import shell_quote
from socket import socket
from dnslib.client import DNSQuestion, DNSRecord
from winreg import OpenKey, QueryValueEx, KEY_READ, KEY_WOW64_64KEY
from glob import glob
from os.path import join, exists, isdir
from typing import Sequence, Callable
from os import rename, remove, chdir, rmdir
from pathlib import Path

import os
import ssl
from urllib.request import urlretrieve
from zipfile import ZipFile

from urllib3 import Timeout

from installer.constants import create_logger, nssm_exe
import sarge

logger = create_logger(__name__)


class ServiceState(Enum):
    RUNNING = 0
    STOPPED = 1
    NOT_EXISTS = 2


def get_exception_details():
    exc_type, exc_value, exc_traceback = sys.exc_info()
    return "\n".join(traceback.format_exception(exc_type, exc_value, exc_traceback))


def get_service_state_windows(service_name: str):
    try:
        service_state = win32serviceutil.QueryServiceStatus(service_name)[1]
        if service_state in [win32service.SERVICE_RUNNING, win32service.SERVICE_START_PENDING]:
            return ServiceState.RUNNING
        else:
            return ServiceState.STOPPED
    except Exception as e:
        if not(e.args[0] == 1060):  # service does not exist
            return ServiceState.NOT_EXISTS
        raise


def stop_service_windows(service_name: str):
    win32serviceutil.StopService(service_name)
    logger.info(f"Successfully stopped {service_name} service.")


def find_mozilla_extension_dir_windows():
    return join(get_app_data_path(), 'Mozilla', 'Extensions', '{ec8030f7-c20a-464f-9b0e-13a3a9e97384}')


def find_cert9_databases_windows():
    r = []
    profiles_dir = join(get_app_data_path(), "Mozilla", "Firefox", "Profiles")
    for profile_dir in glob(os.path.join(profiles_dir, "*")):
        if exists(join(profile_dir, 'cert9.db')):
            r.append(profile_dir)
    return r


def install_service_windows(name: str, service_exe: str, service_args: str, stdout: str, stderr: str, cmd_executor):
    # remove previously configured service
    cmd_executor(f'"{nssm_exe}" remove {name} confirm')
    # add service
    cmd_executor(f'"{nssm_exe}" install {name} {service_exe} {shell_quote(service_args)}',
                 throw_exception=f'Could not install auto-start service for "{name}"')
    # set service properties
    properties = {
        "AppRotateFiles": "1",
        "AppRotateOnline": "1",
        "AppRotateSeconds": "604800",
        "AppRotateBytes": "10000000",
        "AppStderr": stderr,
        "AppStdout": stdout,
    }
    for key, value in properties.items():
        cmd_executor(f'"{nssm_exe}" set {name} "{key}" "{value}"',
                     throw_exception=f'Could not set parameter "{key}" for service "{name}"')
    # start service
    cmd_executor(f'"{nssm_exe}" start {name}',
                 throw_exception=f'Could start service "{name}"')
    logger.info("%s service installed.", name)


def read_reg_key(root, key, value):
    try:
        with OpenKey(root, key, access=KEY_READ | KEY_WOW64_64KEY) as key_handle:
            current_version, _ = QueryValueEx(key_handle, value)
            return current_version
    except OSError as error:
        logger.error(f"Could not find registry key {key}")
        return None


def inspect_platform():
    system_info = platform.system()
    release_info = platform.release()
    logger.debug(f"System: {system_info} Release: {release_info}")


def current_directory():
    return os.getcwd()


def copy_files(src, dest, override=False):
    logger.debug(f"Copying {src} to {dest}..")
    if not os.path.exists(dest):
        os.mkdir(dest)
    for file in glob(src):
        target = os.path.join(dest, os.path.basename(file))
        if os.path.isdir(file):
            copy_files(join(file, '*'), target)
        elif override or not os.path.exists(target):
            copy_file(file, target)


def copy_file(src, dest):
    logger.debug(f"Copying file {src} to {dest}..")
    return shutil.copyfile(src, dest)


def get_desktop_path():
    return os.path.join(os.environ["HOMEPATH"], "Desktop")


def get_app_data_path():
    return os.environ["APPDATA"]


def is_dist():
    return hasattr(sys, '_MEIPASS')


def fix_pyinstaller_root():
    if hasattr(sys, '_MEIPASS'):
        logger.debug(f"PyInstaller executable detected, setting root to {sys._MEIPASS}")
        chdir(sys._MEIPASS)
    else:
        logger.debug(f"Root directory: {current_directory()}")


def write_temp_file(prefix, suffix, content):
    script_file = tempfile.NamedTemporaryFile(suffix=suffix, prefix=prefix, delete=True)
    script_file.close()
    write_file(script_file.name, content)
    return script_file.name


def write_file(filename, content):
    with open(filename, '+w') as f:
        return f.write(content)


def read_file(filename):
    with open(filename, 'r') as f:
        return f.read()


def get_certificate_sha1(cert_file):
    cert = load_certificate(FILETYPE_PEM, bytes(read_file(cert_file), 'utf-8'))
    return str(cert.digest("sha1"), 'utf-8').replace(':', '').lower()


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


def timeout_canceller(timeout: int, canceller=None, canceller2=None) -> Callable[[], bool]:
    start = time.time()

    def tick():
        return (time.time() - start >= timeout) or\
               (canceller is not None and canceller()) or\
               (canceller2 is not None and canceller2())
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


def extract_partial(zipfile, mapper, destination_dir):
    z = ZipFile(zipfile)
    logger.debug("Cherry-picked extracting zip file %s", zipfile)
    for entry in z.infolist():
        for key, value in mapper.items():
            if not entry.orig_filename[-1] == '/' and fnmatch.fnmatchcase(entry.orig_filename, key):
                dest_dir = join(destination_dir, value)
                dest_filename = os.path.basename(Path(entry.orig_filename).resolve())
                os.makedirs(dest_dir, exist_ok=True)
                with z.open(entry.orig_filename) as source, open(join(dest_dir, dest_filename), "wb") as target:
                    shutil.copyfileobj(source, target)
                logger.debug("File %s extracted to %s", dest_filename, dest_dir)
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
    logger.error("Running kiteproxy as admin..")

    def runas():
        params = ' '.join([str((Path(arg).resolve()) if exists(arg) else arg) for arg in sys.argv])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 0)
        logger.error(f"runas {sys.executable} {params}")
    runner = threading.Thread(target=runas, name='process-watchdog', daemon=False)
    runner.start()
    time.sleep(3)


def create_shortcut(shortcut_path: str, working_dir: str, target_path: str, args: str, icon_path: str):
    pythoncom.CoInitialize()
    winshell.CreateShortcut(shortcut_path, target_path, args, working_dir, (icon_path, 0))
    pythoncom.CoInitialize()


def remove_all_files(path, exceptions):
    def rm_internal(ipath):
        for file in glob(join(ipath, '*')):
            if str(Path(file).relative_to(path)) in exceptions:
                continue
            if isdir(file):
                rm_internal(file)
                rmdir(file)
                logger.debug("Removed directory %s", file)
            else:
                remove(file)
            if path == ipath:
                logger.debug("Removed file %s", file)
    rm_internal(path)


def query_dns(host, server):
    dns_request = DNSRecord(q=DNSQuestion(host))
    dns_response = dns_request.send(server)
    return DNSRecord.parse(dns_response).short().split("\n")[0]


def query_google_dns(host):
    google_ip = '74.125.28.139'
    google_dns_headers = {"Host": "dns.google.com"}
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    google_dns_response_raw = requests.get(
        'https://%s/resolve?name=%s&type=%s' % (google_ip, host, 'A'),
        headers=google_dns_headers,
        verify=False)
    google_dns_response = json.loads(google_dns_response_raw.text)['Answer']
    assert len(google_dns_response) > 0
    assert 'data' in google_dns_response[0]
    return google_dns_response[0]['data']


def http_request_with_custom_ip(address, ip=None, proxies=None):
    parts = urlparse(address)
    headers = {"Host": parts[1]}
    new_address = urlunparse((parts[0], ip or parts[1], parts[2], parts[3], parts[4], parts[4]))
    lookup_resp = requests.get(new_address, allow_redirects=False, timeout=Timeout(8), proxies=proxies, headers=headers, verify=False)
    return lookup_resp


def custom_query_https(ip, host_sni, host_name, query_path='/'):
    sock = socket()
    sock.connect((ip, 443))
    try:
        ssl_socket = ssl.SSLSocket(sock, server_hostname=host_sni)
    except ssl.SSLEOFError:
        logger.warn("Connection forcibly closed !")
        return
    ssl_socket.sendall(bytes(f"GET {query_path} HTTP/1.1\r\nHost: {host_name}\r\nConnection: close\r\n\r\n", 'ascii'))
    return '\n'.join(read_socket(ssl_socket))


def read_socket(sock):
    linesep = bytes(os.linesep, 'ascii')
    buffer = sock.recv(4096)
    buffering = True
    while buffering:
        if linesep in buffer:
            (line, buffer) = buffer.split(linesep, 1)
            yield line.decode('utf-8')
        else:
            more = sock.recv(4096)
            if not more:
                buffering = False
            else:
                buffer += more
    if buffer:
        yield buffer


def schedule_remove_after_exit(path):
    current_pid = os.getpid()
    path = str(Path(path).resolve())
    script_content = f"""
@ECHO OFF

echo Waiting for uninstaller to finish.

:loop
tasklist /FI "IMAGENAME eq myapp.exe" 2>NUL 
if "%ERRORLEVEL%"=="0" echo Program is running

tasklist /FI "PID eq {current_pid}" | find /I /N {current_pid}>NUL
if errorlevel 1 (
  goto continue
) else (
  sleep 1
  goto loop
)

:continue
del /Q /s {path}
rd  /Q /s {path}
    """
    script = write_temp_file("autoremove", ".bat", script_content)
    os.chmod(script, 0x0777)
    os.startfile(script)
    # sarge.run(f"\"{script}\"", shell=True, async=True)


__initial_indent = re.compile(r'^\s+', re.MULTILINE)
__whitespace_pattern = re.compile(r'\s+', re.MULTILINE)


def args(string: str):
    return re.sub(__initial_indent, "", re.sub(__whitespace_pattern, " ", string))
