from os.path import join, expanduser
import logging
import sys
import platform

user_home = expanduser('~')
kiteproxy_home = join(expanduser('~'), '.kiteproxy')
kiteproxy_cache = join(kiteproxy_home, '.cache')

kiteproxy_tool_dir = join(kiteproxy_home, 'kiteproxy')

mitmproxy_ver = '3.0.0_6dd336f'
mitmproxy_url = f'https://github.com/kiteproxy/kiteproxy/releases/download/v1.0-alpha/mitmdump_3.0.0_6dd336fcec6dc32c4986b6c20189bf1b2132153c.zip'
mitmproxy_dir = join(kiteproxy_home, 'mitmproxy')
mitmproxy_cert_dir = join(mitmproxy_dir, 'cert')
mitmproxy_cert_pem = join(mitmproxy_cert_dir, 'mitmproxy-ca-cert.pem')
mitmproxy_exe = join(mitmproxy_dir, 'mitmdump.exe')
mitmproxy_script = join(kiteproxy_home, 'kiteproxy-mitm-script.py')
mitmproxy_service_name = 'kiteproxy-mitmproxy'
mitmproxy_certificate_issuer = 'mitmproxy'

secureoperator_ver = '3.0.0'
secureoperator_url = f'https://github.com/fardog/secureoperator/releases/download/v{secureoperator_ver}/secure-operator_windows-386.exe'
secureoperator_host = "127.0.10.53"
secureoperator_google_dns_ips = "74.125.28.100,74.125.28.101,74.125.28.102,74.125.28.113,74.125.28.138,74.125.28.139"
secureoperator_exe = join(kiteproxy_home, 'secureoperator.exe')
secureoperator_service_name = 'kiteproxy-secureoperator'

seven_zip_ver = '18.01'
seven_zip_url = f'http://www.7-zip.org/a/7z{seven_zip_ver.replace(".","")}.exe'
seven_zip_dir = join(kiteproxy_home, "7zip")
seven_zip_exe = join(seven_zip_dir, '7z.exe')

tor_ver = '7.5'
tor_url = f'https://github.com/TheTorProject/gettorbrowser/releases/download/v{tor_ver}/torbrowser-install-{tor_ver}_en-US.exe'
tor_dir = join(kiteproxy_home, "tor")
tor_socks_port = 9150
tor_control_port = 9151
tor_control_password = '16:a8f9c0d1e14b8f68601d9a54f00f9a69960c8041de1dbfc22c9b79091d'
tor_exe = join(tor_dir, 'Browser', 'TorBrowser', 'Tor', 'tor.exe')
tor_service_name = 'kiteproxy-tor'

ffaddcert_ver = '1.0.1'
ffaddcert_url = f'https://github.com/christian-korneck/firefox_add-certs/releases/download/{ffaddcert_ver}/firefox_add-certs.zip'
certutil_exe = join(kiteproxy_home, 'certutil', 'certutil.exe')

# nssm_ver = '2.24'
# nssm_url = f'https://nssm.cc/release/nssm-{nssm_ver}.zip'
# nssm_exe = join(kiteproxy_home, 'nssm.exe')
nssm_exe = join('resources', 'nssm.exe')

switchyomega_ver = '2.5.10'
switchyomega_url = f'https://addons.mozilla.org/firefox/downloads/file/848109/proxy_switchyomega-{switchyomega_ver}-an+fx.xpi'
downloaded_switchyomega_addon = join(kiteproxy_cache, f'switchyomega-{switchyomega_ver}.xpi')

https_everywhere_ver = '2018.1.29'
https_everywhere_url = f'https://addons.mozilla.org/firefox/downloads/file/849530/https_everywhere-{https_everywhere_ver}-an+fx.xpi'
downloaded_https_everywhere_addon = join(kiteproxy_cache, f'https-everywhere-{https_everywhere_ver}.xpi')

firefox_min_ver = '57'
firefox_ver = '57.0.4'
firefox_url_generic = 'https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US'
firefox_url = f'https://download-installer.cdn.mozilla.net/pub/firefox/releases/{firefox_ver}/win64/en-US/Firefox%20Setup%20{firefox_ver}.exe'

is_win = sys.platform.startswith('win')
is_darwin = sys.platform == 'darwin'
is_linux = sys.platform.startswith('linux')
is_ubuntu = is_linux and ('ubuntu' in platform.platform().lower())

all_loggers = []


def exitApp(code=0):
    sys.exit(code)


def create_logger(name):
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(ConsoleHandler())
    all_loggers.append(logger)
    return logger

# ------------------------ LOGGING ------------------------


class ConsoleHandler(logging.StreamHandler):
    """
        Simple log-to-console handle for python logger
    """
    def __init__(self, stream=None):
        super().__init__(stream)
        formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
        self.setLevel(logging.DEBUG)
        self.setFormatter(formatter)
