import traceback
import sys
import logging
from typing import List, Callable
from installer import itasks, mtasks
from installer.constants import create_logger, all_loggers
from installer.base import ConditionalTask, RetrierTask, StopperError
from abc import *
from math import ceil
from installer.base import UserCancelledError
from installer.utils import get_exception_details

logger = create_logger(__name__)

signals_progress = 'progress'
signals_log = 'log'

selected_workflow = 'selected_workflow'
progress_workflow_install = 'install'
progress_workflow_uninstall = 'uninstall'

install_workflow_parameter_clear_cache = 'option_clear_cache'

install_workflow_parameter_option_firefox = 'option_firefox'
install_workflow_parameter_option_switchyomega = 'option_switchyomega'


class LogEmitter(logging.Handler):
    def __init__(self, loggers, progress_signal):
        logging.Handler.__init__(self)
        self._progress_signal = progress_signal
        self.loggers = loggers
        self.setFormatter(logging.Formatter('%(levelname)-8s %(message)s'))

    def emit(self, record):
        self._progress_signal.emit({signals_log: self.format(record)})

    def __enter__(self):
        for lg in self.loggers:
            lg.addHandler(self)

    def __exit__(self, exc_type, exc_val, exc_tb):
        for lg in self.loggers:
            lg.removeHandler(self)


class WorkflowBase:

    def __init__(self, parameters={}, progress_signal=None):
        self._parameters = parameters
        self._progress_signal = progress_signal
        self._cancelled = False
        self._variables = {}

    @abstractmethod
    def _create_steps(self, is_cancelled: Callable[[], bool]) -> List[itasks.InterruptableTask]:
        pass

    def cancel(self):
        self._cancelled = True

    def run(self):
        steps = self._create_steps(lambda: self._cancelled)
        progress_step = ceil(100 / len(steps)) if steps else 100

        def interrupt_if_cancelled():
            if self._cancelled:
                raise UserCancelledError()

        def emit_process_info(percent):
            self._progress_signal.emit({signals_progress: percent})

        with LogEmitter(all_loggers, self._progress_signal):
            try:
                for no, step in enumerate(steps):
                    interrupt_if_cancelled()
                    step.run()
                    emit_process_info(min((no+1)*progress_step, 99))
                emit_process_info(100)
                logger.info('Successfully finished.')
            except UserCancelledError:
                emit_process_info(-1)
                logger.info('User aborted !')
            except StopperError:
                emit_process_info(-1)
            except:
                emit_process_info(-1)
                logger.error('Encountered error !')
                logger.error(get_exception_details())


class InstallWorkflow(WorkflowBase):

    def __init__(self, parameters={}, progress_signal=None):
        super().__init__(parameters, progress_signal)

    def _is_firefox_selected(self):
        return self._parameters[install_workflow_parameter_option_firefox]

    def _is_switchyomega_selected(self):
        return self._parameters[install_workflow_parameter_option_switchyomega]

    def _create_steps(self, is_cancelled: Callable[[], bool]):
        c = is_cancelled
        return [
            # prepare
            itasks.EnsureFirefoxIsClosed(c),
            itasks.EnsureRootPermission(c),
            itasks.EnsureKiteProxyHomeDirectory(c),
            itasks.CopyKiteproxy(c),
            # itasks.FetchNSSM(c),
            itasks.StopKiteProxyServices(c),
            # download
            itasks.FetchMitmproxy(c),
            itasks.FetchSecureOperator(c),
            itasks.FetchKiteproxyMitmScript(c),
            itasks.Fetch7z(c),
            itasks.FetchTor(c),
            ConditionalTask(itasks.FetchAndInstallFirefox(c), self._is_firefox_selected),
            ConditionalTask(itasks.FetchSwitchyOmega(c), self._is_switchyomega_selected),
            ConditionalTask(itasks.FetchHttpsEverywhere(c), self._is_switchyomega_selected),
            itasks.FetchCertUtil(c),
            # install
            RetrierTask(itasks.GenerateMitmCertificates(c)),
            itasks.RemoveRootCertificatesFromWindows(c),
            itasks.InstallRootCertificatesToWindows(c),
            itasks.CreateAutoStartServices(c),
            RetrierTask(itasks.SetSystemDNS(c)),
            itasks.RemoveCertificateFromFirefox(c),
            itasks.InstallCertificateToFirefox(c),
            ConditionalTask(itasks.AddFirefoxAddons(c), self._is_switchyomega_selected),
            itasks.CreateKiteProxyShortcutOnDesktop(c),
        ]


class UninstallWorkflow(WorkflowBase):

    def __init__(self, parameters={}, progress_signal=None):
        super().__init__(parameters, progress_signal)

    def _do_clear_cache(self):
        return self._parameters.get(install_workflow_parameter_clear_cache, None)

    def _create_steps(self, is_cancelled: Callable[[], bool]):
        c = is_cancelled
        return [
            itasks.StopKiteProxyServices(c),
            itasks.RemoveRootCertificatesFromWindows(c),
            itasks.RemoveCertificateFromFirefox(c),
            itasks.RemoveAllFilesExceptMe(c).set_parameters({'clear_cache': self._do_clear_cache()}),
            itasks.SetSystemDNS(c).set_parameters({'dns': 'auto'}),
            itasks.ScheduleKiteproxyRemovalAfterExit(c)
        ]


class MonitorWorkflow(WorkflowBase):

    def __init__(self, parameters={}, progress_signal=None):
        super().__init__(parameters, progress_signal)

    def _is_firefox_selected(self):
        return self._parameters[install_workflow_parameter_option_firefox]

    def _is_switchyomega_selected(self):
        return self._parameters[install_workflow_parameter_option_switchyomega]

    def _create_steps(self, is_cancelled: Callable[[], bool]):
        c = is_cancelled
        sig = self._progress_signal
        return [
            mtasks.CheckDNS(c, sig),
            mtasks.CheckSNIHiding(c, sig),
            mtasks.CheckTor(c, sig),
        ]
