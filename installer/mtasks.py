import re
from _ctypes import Array
import socks
import stem
from stem import Signal
from stem.control import Controller
from enum import Enum
from socket import socket, gethostbyname
from typing import Callable
from os.path import join, exists

import requests
from dnslib.client import DNSQuestion, DNSRecord

from installer import utils, itasks
from installer.base import InterruptableTask, StopperError, UserCancelledError
from installer.constants import *
from installer.utils import query_google_dns, get_service_state_windows, ServiceState, query_dns, \
    http_request_with_custom_ip, get_exception_details, get_certificate_sha1

logger = create_logger(__name__)


signals_progress = 'progress'
signals_log = 'log'
signals_dns = 'dns'
signals_sni = 'sni'
signals_tor = 'tor'
signals_dns_sni_tor__state = "state"
signals_dns_sni_tor__failed = "failed"
signals_dns_sni_tor__params = "params"


class StateTools:
    DEFAULT_ICON = 'wait'

    @staticmethod
    def calculate_message_and_icon(all_states, current_state, is_failed=False, parameters=()):
        try:
            progress = round((all_states.index(current_state) + 1) * 100 / len(all_states))
            calculated_msg = current_state.value
            while True:
                match = re.search('{([^|}]*)\|([^|}]*)}', calculated_msg)
                if match is None:
                    break
                calculated_msg = calculated_msg.replace(match.group(0),
                                                        match.group(2) if is_failed else match.group(1))
            calculated_msg = calculated_msg % parameters
            calculated_msg = calculated_msg + f' ({progress}%)'
            if is_failed:
                calculated_msg = f'<font style="color: red;">{calculated_msg}</font>'
            calculated_icon = 'error' if is_failed else ('ok' if progress >= 99 else 'wait')
        except Exception as e:
            logger.error('Could not format message state %s', current_state, str(e))
            logger.error(get_exception_details())
        return calculated_msg, calculated_icon


class DnsState(Enum):
    FILE_CHECK = '{F|Not f}ound secureoperator.exe'
    SERVICE_EXISTENCE_CHECK = 'Service is {|not }running'
    GOOGLE_DNS_TEST = 'Google DNS {|not }responded to %s query'  # parameter: website (e.g. youtube.com)
    SECURE_OPERATOR_TEST = '{R|Not r}esponded to %s query'  # parameter: website (e.g. youtube.com)
    SYSTEM_DNS_CHECK = 'Network interfaces {|%s }are {all|not} configured'


DnsState.All = [elem for elem in DnsState]


class SniState(Enum):
    FILE_CHECK = '{F|Not f}ound mitmproxy.exe'
    SERVICE_EXISTENCE_CHECK = 'Service is {|not }running'
    WEBSITE_TEST = '{R|Not r}esponded to %s request'  # parameter: website (e.g. youtube.com)
    CERTIFICATE_ON_OS_CHECK = 'Certificate {|not }installed on OS'
    CERTIFICATE_ON_BROWSER_CHECK = 'Certificate {|not }installed on %s'  # parameter: browser (e.g. chrome)


SniState.All = [elem for elem in SniState]


class TorState(Enum):
    FILE_CHECK = '{F|Not f}ound tor.exe'
    SERVICE_EXISTENCE_CHECK = 'Service is {|not }running'
    BOOTSTRAP_CHECK = 'Tor is %s%% bootstrapped {|warn: %s}'
    WEBSITE_TEST = '{R|Not r}esponded to %s request'  # parameter: website (e.g. bbc.com)


TorState.All = [elem for elem in TorState]


class MonitorTask(InterruptableTask):
    def __init__(self, is_cancelled: Callable[[], bool] = lambda: False, custom_signal = None, signal_category: str = 'custom'):
        super().__init__(is_cancelled)
        self._custom_signal = custom_signal
        self._signal_category = signal_category

    def check_cancelled(self):
        if self._is_cancelled():
            raise UserCancelledError()

    def check_file_existence(self, path, state):
        self.check_cancelled()
        file_check_failure = not exists(path)
        logger.info('File "%s" %s exist.', path, 'does' if file_check_failure else 'does not')
        self.signal(state, isfailure=file_check_failure)

    def check_service_running(self, service_name, state):
        self.check_cancelled()
        service_not_running = get_service_state_windows(service_name) != ServiceState.RUNNING
        logger.info('Service "%s" %s.', service_name, 'does not exist' if service_not_running else 'exists')
        self.signal(state, isfailure=service_not_running)

    def signal(self, state, params=(), isfailure=False):
        if self._custom_signal is not None:
            self._custom_signal.emit({
                self._signal_category: {
                    signals_dns_sni_tor__state: state,
                    signals_dns_sni_tor__params: params,
                    signals_dns_sni_tor__failed: isfailure
                }
            })
        if isfailure:
            raise StopperError()

    def run(self):
        pass


class CheckDNS(MonitorTask):

    def __init__(self, is_cancelled: Callable[[], bool] = lambda: False, custom_signal=None):
        super().__init__(is_cancelled, custom_signal, signals_dns)

    @staticmethod
    def is_ip(ip: str):
        return re.match(r"\d+\.\d+\.\d+\.\d+", ip)

    @staticmethod
    def is_clean_ip(ip: str):
        return not ip.startswith('10.10.')

    def run(self):
        logger.debug("Checking google secure dns service..")
        youtube_hostname = 'youtube.com'
        secureoperator_listen_host = '127.0.10.53'

        # step 1
        self.check_file_existence(secureoperator_exe, DnsState.FILE_CHECK)

        # step 2
        self.check_service_running(secureoperator_service_name, DnsState.SERVICE_EXISTENCE_CHECK)

        # step 3
        self.check_cancelled()
        youtube_ip = query_google_dns(youtube_hostname)
        youtube_invalid_ip = not (self.is_ip(youtube_ip) and self.is_clean_ip(youtube_ip))
        logger.info('Direct google DNS query of %s received ip %s', youtube_hostname, youtube_ip)
        self.signal(DnsState.GOOGLE_DNS_TEST, params=youtube_hostname, isfailure=youtube_invalid_ip)

        # step 4
        self.check_cancelled()
        youtube_ip = query_dns(youtube_hostname, secureoperator_listen_host)
        youtube_invalid_ip = not (self.is_ip(youtube_ip) and self.is_clean_ip(youtube_ip))
        logger.info('SecureOperator direct DNS query of %s received ip %s', youtube_hostname, youtube_ip)
        self.signal(DnsState.SECURE_OPERATOR_TEST, params=youtube_hostname, isfailure=youtube_invalid_ip)

        # step 5
        self.check_cancelled()
        ifs = itasks.WindowsGetSystemInterfaces().run()
        ifs_dns = itasks.WindowsGetInterfaceDNS().run()
        for interface in ifs:
            logger.info('Interface "%s" DNS = %s', interface, str(ifs_dns[interface]))
        non_configured_ins = list(filter(lambda inf: not (secureoperator_listen_host in ifs_dns[inf]), ifs))
        interface_dns_failure = len(non_configured_ins) > 0
        params = str(non_configured_ins) if interface_dns_failure else ()
        self.signal(DnsState.SYSTEM_DNS_CHECK, params=params, isfailure=interface_dns_failure)


class CheckSNIHiding(MonitorTask):
    def __init__(self, is_cancelled: Callable[[], bool] = lambda: False, custom_signal=None):
        super().__init__(is_cancelled, custom_signal, signals_sni)

    def run(self):
        google_hostname = 'google.com'
        youtube_hostname = 'youtube.com'
        current_certificate_sha1 = get_certificate_sha1(mitmproxy_cert_pem)

        # step 1
        self.check_file_existence(mitmproxy_exe, SniState.FILE_CHECK)

        # step 2
        self.check_service_running(mitmproxy_service_name, SniState.SERVICE_EXISTENCE_CHECK)

        # step 3
        self.check_cancelled()
        google_ip = gethostbyname(google_hostname)
        received = utils.custom_query_https(google_ip, google_hostname, youtube_hostname)
        response_not_301 = not ('Location:' in received)
        self.signal(SniState.WEBSITE_TEST, params=youtube_hostname, isfailure=response_not_301)
        logger.info('Querying %s with obscured sni received expected response.', youtube_hostname)

        # step 4
        # certificate check on os
        logger.info('SHA-1 hash of kiteproxy certificate is: %s', current_certificate_sha1[:10])
        self.check_cancelled()
        windows_installed_certificates_sha1 = list(itasks.GetRootCertificatesFromWindows().run().values())
        logger.info('SHA-1 hash of mitm certificates installed on windows: %s', str(list(map(lambda c: c[:10], windows_installed_certificates_sha1))))
        certificate_sha1_not_match = not (current_certificate_sha1 in windows_installed_certificates_sha1)
        self.signal(SniState.CERTIFICATE_ON_OS_CHECK, isfailure=certificate_sha1_not_match)

        # step 5
        # certificate check on browsers
        self.check_cancelled()
        firefox_installed_certificates_sha1 = itasks.InstalledCertificatesOnFirefox().run()
        certificate_sha1_not_match = not (current_certificate_sha1 in firefox_installed_certificates_sha1)
        logger.info('SHA-1 hash of mitm certificates installed on firefox: %s', str(list(map(lambda c: c[:10], firefox_installed_certificates_sha1))))
        self.signal(SniState.CERTIFICATE_ON_BROWSER_CHECK, params='firefox', isfailure=certificate_sha1_not_match)


class CheckTor(MonitorTask):
    def __init__(self, is_cancelled: Callable[[], bool] = lambda: False, custom_signal=None):
        super().__init__(is_cancelled, custom_signal, signals_tor)

    @staticmethod
    def split_tor_info(raw_info):
        matches = re.findall('([A-Z0-9]+)(?:=(?:(?:"([^"]+)")|([^ ]*)(?= |$)))?', raw_info)
        return dict(map(lambda match: (match[0], match[1] or match[2] or None), matches))

    def run(self):
        bbc_hostname = 'bbc.com'

        # step 1
        self.check_file_existence(tor_exe, TorState.FILE_CHECK)

        # step 2
        self.check_service_running(tor_service_name, TorState.SERVICE_EXISTENCE_CHECK)

        # step 3
        self.check_cancelled()
        with Controller.from_port(port=tor_control_port) as controller:
            controller.authenticate(password=tor_control_password)
            result = self.split_tor_info(controller.get_info('status/bootstrap-phase'))
            logger.debug('Tor get_info(bootstrap) response: %s', result)
            progress = result['PROGRESS']
            problem = result.get('REASON', 'Unknown')
            check_failed = progress != '100'
            if check_failed:
                msg_params = (progress, problem)
            else:
                msg_params = progress
            if 'WARNING' in result:
                logger.warn('Tor - {%s}', result['WARNING'])
        self.signal(TorState.BOOTSTRAP_CHECK, params=msg_params, isfailure=check_failed)

        # step 4
        self.check_cancelled()
        tor_proxy = f'socks5://127.0.0.1:{tor_socks_port}'
        response = http_request_with_custom_ip(f'http://{bbc_hostname}/', proxies=dict(http=tor_proxy))
        response_not_301 = response.status_code != 301
        logger.info('BBC query through tor proxy response code: %d', response.status_code)
        self.signal(TorState.WEBSITE_TEST, params=bbc_hostname, isfailure=response_not_301)
