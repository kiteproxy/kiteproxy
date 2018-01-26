import logging
import os
import constants
from os import mkdir, rename, removedirs
from os.path import exists
from shutil import copyfile
from distutils.version import LooseVersion
import winreg
import installertools
from constants import *
from mitmscript import kiteproxy_mitm_script_content

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def retry(task, tries):
    def new_task(is_cancelled=None):
        for i in range(tries):
            try:
                task(is_cancelled)
                break
            except InterruptedError:
                raise
            except ChildProcessError:
                logger.level('Retrying.. (%d/%d)', i, tries)
                pass
    return new_task


def ensure_permissions(is_cancelled=None):
    logger.debug("Checking root access..")
    if not installertools.is_root():
        logger.error("No root access !")
        raise PermissionError("KiteProxy installer requires root access !")
    logger.error("Root access.. OK !")


def ensure_kite_proxy_home_dirs(is_cancelled=None):
    logger.debug("Creating KiteProxy directories..")
    if not exists(kiteproxy_home):
        mkdir(kiteproxy_home)
        logger.debug("KiteProxy home dir created at: %s", kiteproxy_home)
    else:
        logger.debug("KiteProxy home dir already was there: %s", kiteproxy_home)
    if not exists(kiteproxy_cache):
        mkdir(kiteproxy_cache)
        logger.debug("KiteProxy download cache dir created at: %s", kiteproxy_cache)
    else:
        logger.debug("KiteProxy download cache dir already there at: %s", kiteproxy_home)


def stop_background_services(is_cancelled=None):
    nssm_executable = join(kiteproxy_home, 'nssm.exe')

    def stop_service(name: str):
        cmd = f'"{nssm_executable}" stop {name}'
        installertools.run(cmd, is_cancelled)

    stop_service('kiteproxy-secureoperator')
    stop_service('kiteproxy-mitmproxy')

# ----------------------------- download phase ----------------------------------


def ensure_mitmproxy_is_downloaded(is_cancelled=None):
    logger.debug("Checking Mitmproxy TLS Transformer files..")
    if not exists(join(kiteproxy_home, 'mitmproxy', 'mitmdump.exe')):
        downloaded_mitmproxy_archive = join(kiteproxy_cache, f'mitmproxy-{mitmproxy_ver}.zip')
        installertools.download(mitmproxy_url, downloaded_mitmproxy_archive, is_cancelled)
        if not exists(join(kiteproxy_home, 'mitmproxy')):
            mkdir(join(kiteproxy_home, 'mitmproxy'))
        if not exists(join(kiteproxy_home, 'mitmproxy', 'cert')):
            mkdir(join(kiteproxy_home, 'mitmproxy', 'cert'))
        installertools.extract_all(downloaded_mitmproxy_archive, join(kiteproxy_home, 'mitmproxy'))
        logger.info("Mitmproxy TLS Transformer downloaded and extracted successfully.")
    else:
        logger.info("Mitmproxy TLS Transformer files.. OK !")


# def ensure_dnscrypt_is_downloaded(is_cancelled=None):
#     logger.debug("Checking DNSCrypt Secure DNS Proxy files..")
#     if not exists(join(kiteproxy_home, 'dnscrypt', 'dnscrypt-proxy.exe')):
#         downloaded_dnscrypt_archive = join(kiteproxy_cache, f'dnscrypt-{secureoperator_ver}.zip')
#         installertools.download(secureoperator_url, downloaded_dnscrypt_archive, is_cancelled)
#         installertools.extract_all(downloaded_dnscrypt_archive, kiteproxy_home)
#         rename(join(kiteproxy_home, f'dnscrypt-proxy-win64'), join(kiteproxy_home, f'dnscrypt'))
#         logger.info("DNSCrypt downloaded and extracted successfully.")
#     else:
#         logger.info("DNSCrypt ... already downloaded !")


def ensure_secureoperator_is_downloaded(is_cancelled=None):
    logger.debug("Checking Secure-Operator Google Secure DNS Proxy file..")
    if not exists(join(kiteproxy_home, 'secureoperator.exe')):
        downloaded_secureoperator_executable = join(kiteproxy_cache, f'secure-operator_{secureoperator_ver}.exe')
        installertools.download(secureoperator_url, downloaded_secureoperator_executable, is_cancelled)
        copyfile(downloaded_secureoperator_executable, join(kiteproxy_home, 'secureoperator.exe'))
        logger.info("Secure-Operator downloaded and extracted successfully.")
    else:
        logger.debug("Secure-Operator files ... OK !")


def ensure_nssm_is_downloaded(is_cancelled=None):
    logger.debug("Checking NSSM service manager files..")
    if not exists(join(kiteproxy_home, 'nssm.exe')):
        downloaded_nssm_archive = join(kiteproxy_cache, f'nssm-{nssm_ver}.zip')
        installertools.download(nssm_url, downloaded_nssm_archive, is_cancelled)
        installertools.extract(downloaded_nssm_archive, {f'nssm-{nssm_ver}/win64/nssm.exe': kiteproxy_home})
        rename(join(kiteproxy_home, f'nssm-{nssm_ver}/win64/nssm.exe'),
               join(kiteproxy_home, f'nssm.exe'))
        removedirs(join(kiteproxy_home, f'nssm-{nssm_ver}/win64'))
        logger.info("NSSM downloaded and extracted successfully.")
    else:
        logger.info("NSSM files ... OK !")


def ensure_kiteproxy_mitm_script_is_downloaded(is_cancelled=None):
    logger.debug("Checking KiteProxy script for Mitm file..")
    if not exists(join(kiteproxy_home, 'kiteproxy-mitm-script.py')):
        installertools.write_file(join(kiteproxy_home, 'kiteproxy-mitm-script.py'), kiteproxy_mitm_script_content)
        logger.info("KiteProxy script file for mitmproxy written successfully.")
    else:
        logger.info("KiteProxy script file for mitmproxy ... OK !")


def ensure_firefox_installed(is_cancelled=None):
    logger.debug("Checking Firefox installation..")
    try:
        current_version = installertools.read_reg_key(winreg.HKEY_LOCAL_MACHINE, 'Software\\Mozilla\\Mozilla Firefox', "")
        logger.info("Firefox installation detected ... version %s !", current_version)
        minimum_version = '57'
        if LooseVersion(current_version) < minimum_version:
            logger.info("Firefox is going to be upgraded to version %s !", constants.firefox_ver)
            raise ValueError("Needs upgrade")
    except:
        mozilla_installation_file = join(kiteproxy_cache, f'firefox-{firefox_ver}.exe')
        installertools.download(firefox_url, mozilla_installation_file, is_cancelled)
        install_config_file = installertools.write_temp_file('firefox_install', '.ini', """
[Install]
MaintenanceService=true
        """.strip())
        firefox_install_cmd = f'"{mozilla_installation_file}" "/INI={install_config_file}"'
        logger.debug(f"Installing firefox: %s", firefox_install_cmd)
        installertools.run(firefox_install_cmd, is_cancelled)
        pass


def ensure_ffaddcert_is_downloaded(is_cancelled=None):
    logger.debug("Checking firefox-add-certificate.")
    if not exists(join(kiteproxy_home, 'ffaddcert', 'add-certs.cmd')):
        downloaded_ffaddcert_archive = join(kiteproxy_cache, f'ffaddcert-{ffaddcert_ver}.zip')
        installertools.download(ffaddcert_url, downloaded_ffaddcert_archive, is_cancelled)
        installertools.extract_all(downloaded_ffaddcert_archive, kiteproxy_home)
        rename(join(kiteproxy_home, 'firefox_add-certs'), join(kiteproxy_home, 'ffaddcert'))
        installertools.remove_all_files(join(kiteproxy_home, 'ffaddcert', 'cacert', '*'))
        logger.info("Firefox-add-certificate downloaded and extracted successfully.")
    else:
        logger.info("Firefox-add-certificate ... already downloaded !")


def ensure_foxyproxy_is_downloaded(is_cancelled=None):
    logger.debug("Checking foxy-proxy automatic firefox proxy relay.")
    installertools.download(foxyproxy_url, downloaded_foxyproxy_addon, is_cancelled)

# ----------------------------- install phase ----------------------------------


def create_mitm_certificates(is_cancelled=None):
    def certificate_created():
        return exists(join(kiteproxy_home, 'mitmproxy', 'cert', 'mitmproxy-ca-cert.pem'))

    if not certificate_created():
        mitmdump_exec = join(kiteproxy_home, 'mitmproxy', 'mitmdump.exe')
        ca_dir = join(kiteproxy_home, 'mitmproxy', 'cert')
        logger.info("Generating mitmproxy root certificate..")
        mitmdump_noserver_run = f'"{mitmdump_exec}" --no-server --verbose --set "cadir={ca_dir}"'
        try:
            return_code = installertools.run(mitmdump_noserver_run, installertools.timeout_canceller(30, certificate_created))
            if not return_code == 0 and not certificate_created():
                raise ChildProcessError('Problem with mitmproxy generating certificate !')
        except InterruptedError:
            if not certificate_created():
                if is_cancelled is not None and is_cancelled():
                    return
                else:
                    raise InterruptedError('Certificate creation timeout !')
        logger.info("Mitmproxy root certificate generated successfully at %s", join(kiteproxy_home, 'mitmproxy', 'cert'))
    else:
        logger.info("Mitmproxy root certificate.. already exists !")


def install_root_certificate_on_os(is_cancelled=None):
    logger.info("Installing mitmproxy root certificate on windows..")
    root_certificate = join(kiteproxy_home, 'mitmproxy', 'cert', 'mitmproxy-ca-cert.pem')
    cmd = f'certutil.exe -delstore -enterprise -f -v root "{root_certificate}"'
    installertools.run(cmd, is_cancelled)
    cmd = f'certutil.exe -addstore -enterprise -f -v root "{root_certificate}"'
    if not installertools.run(cmd, is_cancelled) == 0:
        raise ChildProcessError('Problem installing certificate on windows !')


def install_background_services(is_cancelled=None):
    nssm_executable = join(kiteproxy_home, 'nssm.exe')

    def install_service(name: str, service_cmd: str, stdout: str, stderr: str):
        # remove previously configured service
        cmd = f'"{nssm_executable}" remove {name} confirm'
        installertools.run(cmd, is_cancelled)
        # add service
        cmd = f'"{nssm_executable}" install {name} {service_cmd}'
        installertools.run(cmd, is_cancelled)
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
            cmd = f'"{nssm_executable}" set {name} "{key}" "{value}"'
            installertools.run(cmd, is_cancelled)
        # start service
        cmd = f'"{nssm_executable}" start {name}'
        installertools.run(cmd, is_cancelled)
        logger.info("%s service installed.", name)

    secureoperator_executable = join(kiteproxy_home, 'secureoperator.exe')
    secureoperator_stdout_log = join(kiteproxy_home, 'secureoperator.stdout.log')
    secureoperator_stderr_log = join(kiteproxy_home, 'secureoperator.stderr.log')
    secureoperator_opts = installertools.args(f'''
    -no-pad
    -listen {secureoperator_host}:53
    -endpoint-ips "{secureoperator_google_dns_ips}"
    ''')

    _kiteproxy_mitm_script = join(kiteproxy_home, 'kiteproxy-mitm-script.py')
    _mitmproxy_cadir = join(kiteproxy_home, 'mitmproxy', 'cert')
    mitmproxy_executable = join(kiteproxy_home, 'mitmproxy', 'mitmdump.exe')
    mitmproxy_stdout_log = join(kiteproxy_home, 'mitmproxy.stdout.log')
    mitmproxy_stderr_log = join(kiteproxy_home, 'mitmproxy.stderr.log')
    mitmproxy_opts = installertools.args(f'''
    --listen-port 9990
    --ssl-insecure
    --set stream_large_bodies=50k
    --script "{_kiteproxy_mitm_script}"
    --set "cadir={_mitmproxy_cadir}"
    ''')

    install_service('kiteproxy-secureoperator', f'{secureoperator_executable} {secureoperator_opts}', secureoperator_stdout_log, secureoperator_stderr_log)
    install_service('kiteproxy-mitmproxy', f'{mitmproxy_executable} {mitmproxy_opts}', mitmproxy_stdout_log, mitmproxy_stderr_log)


def set_active_interface_dns(is_cancelled=None, resolver=secureoperator_host):
    def is_active(inf):
        return inf[0] == 'Enabled' and inf[1] == 'Connected'
    connected_interface_names = [inf[3] for inf in installertools.get_interfaces_info() if is_active(inf)]
    for interface in connected_interface_names:
        if resolver == 'auto':
            param = 'dhcp'
        else:
            param = f'static {resolver} primary'
        logger.info("Setting dns %s on %s..", resolver, interface)
        cmd = f'netsh interface ip set dnsservers "{interface}" {param}'
        if not installertools.run(cmd, is_cancelled) == 0:
            raise ChildProcessError('Problem configuring interface DNS !')


def add_mitm_certificate_to_firefox(is_cancelled=None, pem_file=join(kiteproxy_home, 'mitmproxy', 'cert', 'mitmproxy-ca-cert.pem')):
    logger.info("Installing mitm root certificate on firefox..")
    installertools.remove_all_files(join(kiteproxy_home, 'ffaddcert', 'cacert'))
    copyfile(pem_file, join(kiteproxy_home, 'ffaddcert', 'cacert', 'mitmproxy-ca-cert.pem'))
    ffaddcert = join(kiteproxy_home, 'ffaddcert', 'add-certs.cmd')
    cmd = f'"{ffaddcert}"'
    installertools.run(cmd, is_cancelled)


def add_foxyproxy_to_firefox(is_cancelled=None, xpi_file=downloaded_foxyproxy_addon):
    logger.info("Installing Foxyproxy on Firefox..")
    try:
        ff_key = 'Software\\Mozilla\\Mozilla Firefox'
        ff_version = installertools.read_reg_key(winreg.HKEY_LOCAL_MACHINE, ff_key, 'CurrentVersion')
        ff_path = installertools.read_reg_key(winreg.HKEY_LOCAL_MACHINE, f'{ff_key}\\{ff_version}\\Main', 'PathToExe')
        assert ff_path is not None and len(ff_path) > 0
    except:
        ff_path = join(os.environ['PROGRAMFILES'], 'Mozilla Firefox', 'firefox.exe')
    cmd = f'"{ff_path}" "{xpi_file}"'
    installertools.run(cmd, is_cancelled)
