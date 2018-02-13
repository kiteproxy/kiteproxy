import os
import re
import winreg
import pathlib
from distutils.version import LooseVersion
from glob import glob
from os import mkdir, rename, removedirs
from os.path import exists, sep
from re import RegexFlag
from shutil import copyfile
from typing import Callable

import ifaddr
import psutil

from installer import utils, constants
from installer.utils import get_app_data_path, get_service_state_windows, stop_service_windows, install_service_windows, \
    ServiceState, find_cert9_databases_windows, find_mozilla_extension_dir_windows
from installer.base import InterruptableTask, UserCancelledError, ExternalProcessError, StopperError
from installer.constants import *
from resources.mitmscript import kiteproxy_mitm_script_content

logger = create_logger(__name__)


class EnsureFirefoxIsClosed(InterruptableTask):
    def run(self):
        for pid in psutil.pids():
            try:
                if "firefox.exe" in psutil.Process(pid).name():
                    logger.error("Firefox is running, please close it first !")
                    raise StopperError()
            except:  # ignore process not found bug
                pass


class EnsureRootPermission(InterruptableTask):
    def run(self):
        logger.debug("Checking root access..")
        if not utils.is_root():
            logger.error("No root access !")
            raise PermissionError("KiteProxy installer requires root access !")
        logger.info("Root access.. OK !")


class EnsureKiteProxyHomeDirectory(InterruptableTask):
    def run(self):
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


class StopKiteProxyServices(InterruptableTask):
    def run(self):
        logger.debug(f"Stopping kiteproxy services..")
        for service_name in [secureoperator_service_name, mitmproxy_service_name, tor_service_name]:
            try:
                if get_service_state_windows(service_name) != ServiceState.NOT_EXISTS:
                    stop_service_windows(service_name)
            except Exception as e:
                logger.warn(e)
                pass


# ----------------------------- download phase ----------------------------------


class FetchMitmproxy(InterruptableTask):
    def run(self):
        logger.debug("Checking Mitmproxy TLS Transformer files..")
        if not exists(mitmproxy_exe):
            downloaded_mitmproxy_archive = join(kiteproxy_cache, f'mitmproxy-{mitmproxy_ver}.zip')
            self.download(mitmproxy_url, downloaded_mitmproxy_archive)
            if not exists(mitmproxy_dir):
                mkdir(mitmproxy_dir)
            if not exists(mitmproxy_cert_dir):
                mkdir(mitmproxy_cert_dir)
            utils.extract_all(downloaded_mitmproxy_archive, mitmproxy_dir)
            logger.info("Mitmproxy TLS Transformer downloaded and extracted successfully.")
        else:
            logger.info("Mitmproxy TLS Transformer files.. OK !")


class FetchSecureOperator(InterruptableTask):
    def run(self):
        logger.debug("Checking Secure-Operator Google Secure DNS Proxy file..")
        if not exists(secureoperator_exe):
            downloaded_secureoperator_executable = join(kiteproxy_cache, f'secure-operator_{secureoperator_ver}.exe')
            self.download(secureoperator_url, downloaded_secureoperator_executable)
            copyfile(downloaded_secureoperator_executable, secureoperator_exe)
            logger.info("Secure-Operator downloaded and extracted successfully.")
        else:
            logger.debug("Secure-Operator files ... OK !")


class FetchNSSM(InterruptableTask):
    def run(self):
        logger.debug("Checking NSSM service manager files..")
        if not exists(nssm_exe):
            downloaded_nssm_archive = join(kiteproxy_cache, f'nssm-{nssm_ver}.zip')
            self.download(nssm_url, downloaded_nssm_archive)
            utils.extract_partial(downloaded_nssm_archive, {f'nssm-{nssm_ver}/win64/nssm.exe': ''}, kiteproxy_home)
            logger.info("NSSM downloaded and extracted successfully.")
        else:
            logger.info("NSSM files ... OK !")


class Fetch7z(InterruptableTask):
    def run(self):
        logger.debug("Checking 7z extractor files..")
        if not exists(seven_zip_exe):
            downloaded_7z_setup = join(kiteproxy_cache, f'7z-{seven_zip_ver}-setup.exe')
            self.download(seven_zip_url, downloaded_7z_setup)
            self.execute(f'"{downloaded_7z_setup}" /S "/D={seven_zip_dir}{sep}" ')
            logger.info("7z downloaded and extracted successfully.")
        else:
            logger.info("7z files ... OK !")


class FetchTor(InterruptableTask):
    def run(self):
        logger.debug("Checking tor files..")
        if not exists(tor_exe):
            tor_setup = join(kiteproxy_cache, f'tor-{tor_ver}-setup.exe')
            self.download(tor_url, tor_setup)
            seven_zip = seven_zip_exe
            extract_filters = ["Browser\TorBrowser\Tor", "Browser\TorBrowser\Data\Tor"]
            self.execute(f'"{seven_zip}" x "{tor_setup}" "-o{tor_dir}" {" ".join(extract_filters)}')
            logger.info("Tor downloaded and extracted successfully.")
        else:
            logger.info("Tor files ... OK !")


class FetchKiteproxyMitmScript(InterruptableTask):
    def run(self):
        logger.debug("Checking KiteProxy script for Mitm file..")
        if not exists(mitmproxy_script):
            utils.write_file(mitmproxy_script, kiteproxy_mitm_script_content)
            logger.info("KiteProxy script file for mitmproxy written successfully.")
        else:
            logger.info("KiteProxy script file for mitmproxy ... OK !")


class FetchAndInstallFirefox(InterruptableTask):
    _firefox_minimum_version = LooseVersion(firefox_min_ver)

    def run(self):
        logger.debug("Checking Firefox installation..")
        current_version = utils.read_reg_key(winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Mozilla\\Mozilla Firefox", "")
        if current_version is not None:
            logger.info("Firefox installation detected ... version %s !", current_version)
            if LooseVersion(current_version) >= self._firefox_minimum_version:
                return
            else:
                logger.info("Firefox is going to be upgraded to version %s !", constants.firefox_ver)
        mozilla_installation_file = join(kiteproxy_cache, f'firefox-{firefox_ver}.exe')
        self.download(firefox_url, mozilla_installation_file)
        install_config_file = utils.write_temp_file('firefox_install', '.ini', """
[Install]
MaintenanceService=true
        """.strip())
        logger.debug(f"Installing firefox..")
        self.execute(f'"{mozilla_installation_file}" "/INI={install_config_file}"')
        pass


class FetchCertUtil(InterruptableTask):
    def run(self):
        logger.debug("Checking firefox-add-certificate.")
        if not exists(certutil_exe):
            downloaded_ffaddcert_archive = join(kiteproxy_cache, f'ffaddcert-{ffaddcert_ver}.zip')
            self.download(ffaddcert_url, downloaded_ffaddcert_archive)
            utils.extract_partial(downloaded_ffaddcert_archive, {'firefox_add-certs/bin/*': 'certutil'}, kiteproxy_home)
            logger.info("Firefox-add-certificate downloaded and extracted successfully.")
        else:
            logger.info("Firefox-add-certificate ... already downloaded !")


class FetchSwitchyOmega(InterruptableTask):
    def run(self):
        logger.debug("Checking SwitchyOmega automatic firefox proxy switcher.")
        self.download(switchyomega_url, downloaded_switchyomega_addon)


class FetchHttpsEverywhere(InterruptableTask):
    def run(self):
        logger.debug("Checking HttpsEverywhere automatic firefox proxy switcher.")
        self.download(https_everywhere_url, downloaded_https_everywhere_addon)


class CopyKiteproxy(InterruptableTask):
    def run(self):
        logger.debug("Copying Kiteproxy..")
        if not exists(join(kiteproxy_tool_dir, 'setup.exe')) and utils.is_dist():
            utils.copy_files(join(utils.current_directory(), "*"), kiteproxy_tool_dir)
            logger.info("Kiteproxy copied successfully.")
        else:
            logger.info("Kiteproxy... already copied !")


# ----------------------------- install phase ----------------------------------


class GenerateMitmCertificates(InterruptableTask):
    @staticmethod
    def certificate_created():
        return exists(join(kiteproxy_home, 'mitmproxy', 'cert', 'mitmproxy-ca-cert.pem'))

    def run(self):
        if not self.certificate_created():
            create_expiration_canceller = utils.timeout_canceller(30, self.certificate_created, self._is_cancelled)
            logger.info("Generating mitmproxy root certificate..")
            try:
                cmd = f'"{mitmproxy_exe}" --no-server --verbose --set "cadir={mitmproxy_cert_dir}"'
                res = self.execute(cmd, create_expiration_canceller,
                                   throw_exception=f'Problem with mitmproxy generating certificate !')
                logger.info("Mitmproxy root certificate generated successfully at %s", join(kiteproxy_home, 'mitmproxy', 'cert'))
                return res
            except UserCancelledError:
                if not self.certificate_created():
                    raise ExternalProcessError('Problem with mitmproxy generating certificate (timeout) !')
                else:
                    pass
        else:
            logger.info("Mitmproxy root certificate.. already exists !")


class GetRootCertificatesFromWindows(InterruptableTask):
    @staticmethod
    def split_certificates(raw_info):
        matches = re.findall("={4,} Certificate ([0-9]+) ={4,}\nSerial Number:.*\nIssuer:.*O=%s,.*\n(?:(?:(?!sha1).)*\n)+.*sha1.*([0-9a-fA-F]{40})" % mitmproxy_certificate_issuer, raw_info)
        return dict(map(lambda match: (match[0], match[1]), matches))

    def run(self):
        logger.info("Installing mitmproxy root certificate on windows..")
        _, output, _ = self.execute('certutil.exe -store -enterprise root',
                                    throw_exception='Problem installing certificate on windows !')
        root_certificates = self.split_certificates(output)
        return root_certificates


class RemoveRootCertificatesFromWindows(InterruptableTask):
    def run(self):
        mitm_certificates = GetRootCertificatesFromWindows(self._is_cancelled).run()
        for idx, name in mitm_certificates.items():
            self.execute(f'certutil.exe -delstore -enterprise -f root {idx}',
                         throw_exception='Problem removing certificate from windows !')


class InstallRootCertificatesToWindows(InterruptableTask):
    def run(self):
        logger.info("Installing mitmproxy root certificate on windows..")
        self.execute(f'certutil.exe -addstore -enterprise -f -v root "{mitmproxy_cert_pem}"',
                     throw_exception='Problem installing certificate on windows !')


class CreateAutoStartServices(InterruptableTask):
    def run(self):
        secureoperator_stdout_log = join(kiteproxy_home, 'secureoperator.stdout.log')
        secureoperator_stderr_log = join(kiteproxy_home, 'secureoperator.stderr.log')
        secureoperator_opts = utils.args(f'''
        -no-pad
        -listen {secureoperator_host}:53
        -endpoint-ips "{secureoperator_google_dns_ips}"
        ''')

        mitmproxy_stdout_log = join(kiteproxy_home, 'mitmproxy.stdout.log')
        mitmproxy_stderr_log = join(kiteproxy_home, 'mitmproxy.stderr.log')
        mitmproxy_opts = utils.args(f'''
        --listen-port 9990
        --ssl-insecure
        --set stream_large_bodies=50k
        --script "{mitmproxy_script}"
        --set "cadir={mitmproxy_cert_dir}"
        ''')

        _tor_home = join(tor_dir, 'Browser')
        _tor_bin_dir = join(_tor_home, 'TorBrowser', 'Tor')
        _tor_data_dir = join(_tor_home, 'TorBrowser', 'Data', 'Tor')
        tor_stdout_log = join(kiteproxy_home, 'tor.stdout.log')
        tor_stderr_log = join(kiteproxy_home, 'tor.stderr.log')
        client_transport = f'"obfs4 exec {join(_tor_bin_dir, "PluggableTransports", "obfs4proxy.exe")}"'
        tor_opts = utils.args(f'''
         --defaults-torrc "{join(_tor_data_dir,"torrc-defaults")}"
         -f "{join(_tor_data_dir,"torrc")}"
         DataDirectory "{_tor_data_dir}"
         GeoIPFile "{join(_tor_data_dir,"geoip")}"
         GeoIPv6File "{join(_tor_data_dir,"geoip6")}"
         ControlPort {tor_control_port}
         HashedControlPassword {tor_control_password}
         SocksPort 127.0.0.1:{tor_socks_port}
         ClientTransportPlugin {client_transport}
        ''')

        install_service_windows(secureoperator_service_name, secureoperator_exe, secureoperator_opts,
                                secureoperator_stdout_log, secureoperator_stderr_log, self.execute)
        install_service_windows(mitmproxy_service_name, mitmproxy_exe, mitmproxy_opts,
                                mitmproxy_stdout_log, mitmproxy_stderr_log, self.execute)
        install_service_windows(tor_service_name, tor_exe, tor_opts,
                                tor_stdout_log, tor_stderr_log, self.execute)


class WindowsGetSystemInterfaces(InterruptableTask):
    def run(self):
        logger.debug("Fetching interface information..")

        collected_interfaces = []
        for adapter in ifaddr.get_adapters():
            if not [item for item in ['tap', 'virtual', 'loop', 'pseudo'] if item in adapter.nice_name.lower()]:
                for ipobj in adapter.ips:
                    if not str(ipobj.ip).startswith('169.254') and ipobj.network_prefix <= 32:
                        collected_interfaces.append(ipobj.nice_name)

        logger.debug("Retrieved interfaces information: " + ", ".join(collected_interfaces))
        return collected_interfaces


class WindowsGetInterfaceDNS(InterruptableTask):
    def run(self):
        logger.debug("Fetching interface dns settings..")
        _, stdout, _ = self.execute('netsh interface ip show dnsservers',
                                    throw_exception='Could not get interface DNS settings')
        raw_items = stdout.split("\n\n")
        result = dict()
        for raw_item in raw_items:
            match = re.search("configuration(?:[^\n\":]*)interface \"([^\"]+)\"", raw_item, flags=RegexFlag.IGNORECASE)
            iname = match.group(1)
            dns_match = re.search("^([^\n\":]*dns[^\n\":]*server[^\n\":]*):([^:\"\n]+(?:\n[^:\"\n]+(?=\n|$))*)", raw_item, flags=RegexFlag.IGNORECASE | RegexFlag.MULTILINE)
            is_dhcp = 'DHCP' in dns_match.group(1).upper()
            ips = re.split('\\s+', dns_match.group(2).strip())
            result[iname] = 'auto' if is_dhcp or ips == ['None'] else ips
        return result


class WindowsSetInterfaceDNS(InterruptableTask):
    def run(self):
        resolver = self.get_parameters().get('dns', secureoperator_host)
        connected_interface_names = self.get_parameters()['input']
        for interface in connected_interface_names:
            if resolver == 'auto':
                param = 'dhcp'
            else:
                param = f'static {resolver} primary'
            logger.info("Setting dns %s on %s..", resolver, interface)
            self.execute(f'netsh interface ip set dnsservers "{interface}" {param}',
                         throw_exception='Encountered problem during configuration of the interface DNS !')


def SetSystemDNS(is_cancelled: Callable[[], bool]):
    return WindowsGetSystemInterfaces(is_cancelled) | WindowsSetInterfaceDNS(is_cancelled)


class InstalledCertificatesOnFirefox(InterruptableTask):
    @staticmethod
    def split_certutil_cert_info(raw_info):
        matches = re.findall(r'SHA1.*\n\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2})+)', raw_info)
        return list(map(lambda match: match.lower().replace(':', ''), matches))

    def run(self):
        for cert9_dir in find_cert9_databases_windows():
            profile_name = os.path.basename(cert9_dir)
            _, output, _ = self.execute(f'"{certutil_exe}" -L -n "{mitmproxy_certificate_issuer}" -d "sql:{cert9_dir}"')
            mitm_sha1_signatures = self.split_certutil_cert_info(output)
            return mitm_sha1_signatures


class RemoveCertificateFromFirefox(InterruptableTask):
    def run(self):
        logger.info("Installing mitm root certificate on firefox..")
        for cert9_dir in find_cert9_databases_windows():
            self.execute(f'"{certutil_exe}" -D -n "{mitmproxy_certificate_issuer}" -d "sql:{cert9_dir}"')


class InstallCertificateToFirefox(InterruptableTask):
    def run(self):
        logger.info("Installing mitm root certificate on firefox..")
        for cert9_dir in find_cert9_databases_windows():
            self.execute(f'"{certutil_exe}" -A -n "{mitmproxy_certificate_issuer}" -t "TCu,Cu,Tu" -i "{mitmproxy_cert_pem}" -d "sql:{cert9_dir}"',
                         throw_exception=f'Could not install certificate to firefox profile at {cert9_dir}')


class AddFirefoxAddons(InterruptableTask):
    def run(self):
        ffext_autoinstall_path = find_mozilla_extension_dir_windows()
        os.path.exists(ffext_autoinstall_path) or os.mkdir(ffext_autoinstall_path)
        copyfile(downloaded_https_everywhere_addon, join(ffext_autoinstall_path, 'https-everywhere@eff.org.xpi'))
        copyfile(downloaded_switchyomega_addon, join(ffext_autoinstall_path, 'switchyomega@feliscatus.addons.mozilla.org.xpi'))
# xpi_file = downloaded_switchyomega_addon
# logger.info("Installing Foxyproxy on Firefox..")
# ff_path = None
# ff_version = utils.read_reg_key(winreg.HKEY_LOCAL_MACHINE, 'Software\\Mozilla\\Mozilla Firefox', 'CurrentVersion')
# if ff_version:
#     ff_path = utils.read_reg_key(winreg.HKEY_LOCAL_MACHINE, f'Software\\Mozilla\\Mozilla Firefox\\{ff_version}\\Main', 'PathToExe')
# if not ff_path:
#     ff_path = join(os.environ['PROGRAMFILES'], 'Mozilla Firefox', 'firefox.exe')
# self.execute(f'"{ff_path}" "{xpi_file}"', dont_log_stderr=True, dont_log_stdout=True, async=True)


class CreateKiteProxyShortcutOnDesktop(InterruptableTask):
    def run(self):
        utils.create_shortcut(
            shortcut_path=join(utils.get_desktop_path(), "KiteProxy.lnk"),
            working_dir=kiteproxy_tool_dir,
            target_path=join(kiteproxy_tool_dir, "setup.exe"),
            args="--monitor",
            icon_path=join(kiteproxy_tool_dir, "setup.exe"),
        )


# ----------------------------- uninstall phase ----------------------------------


class RemoveAllFilesExceptMe(InterruptableTask):
    def run(self):
        logger.debug("Removing all kiteproxy files except current process..")
        should_clear_cache = self.get_parameters()['clear_cache']
        exceptions = ['kiteproxy'] + (['.cache'] if should_clear_cache else [])
        utils.remove_all_files(join(kiteproxy_home), exceptions)


class ScheduleKiteproxyRemovalAfterExit(InterruptableTask):
    def run(self):
        logger.debug("Scheduling kiteproxy removal after exit..")
        utils.schedule_remove_after_exit(join(kiteproxy_home, 'kiteproxy'))
