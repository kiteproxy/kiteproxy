import os
from PyQt5 import uic, QtCore
from PyQt5.QtGui import QTextCursor, QIcon
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QPushButton, QCheckBox, QTextEdit, QProgressBar, \
    QStackedWidget, QLabel, QFileDialog
import webbrowser
import sys
import math
import installer
import installertools
import logging
import threading
import traceback
from typing import *
from abc import *
from enum import Enum
from installertools import fix_pyinstaller_root, is_root, windows_run_as_admin, windows_correct_icon
import resources_rc

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# ----------------------------- installer window ------------------------------

_side_step_active_style = 'background: #747474;\nfont-weight: bold;\ncolor: white;'
_side_step_inactive_style = 'font-weight: normal;\ncolor: #a2a2a2;'


class InstallerWindow(QMainWindow):

    def __init__(self):
        QMainWindow.__init__(self)
        uic.loadUi('resources/window.ui', self)
        self.action_btn.clicked.connect(self.action_button_click)        
        OptionsPage(self).set_page()

    def action_button_click(self):
        self.page.action()


# ---------------------------- options page state -------------------------

class Page(QtCore.QObject):
    installer_window: InstallerWindow

    def __init__(self, installer_wnd: InstallerWindow, index: int, title: str, action_btn_label: str):
        QtCore.QObject.__init__(self)
        self.installer_window = installer_wnd
        self.index = index
        self.title = title
        self.action_btn_label = action_btn_label

    def set_page(self):
        self.installer_window.page = self
        self._activate()

    def _activate(self):
        self.installer_window.stackedWidget.setCurrentIndex(self.index)
        side_steps = [self.installer_window.side_step0, self.installer_window.side_step1, self.installer_window.side_step2]
        for idx, side_step in enumerate(side_steps):
            side_step.setStyleSheet(_side_step_active_style if idx == self.index else _side_step_inactive_style)
        self.installer_window.title.setText(self.title)
        self.installer_window.action_btn.setText(self.action_btn_label)
        self.post_activate()

    def post_activate(self):
        pass

    @abstractmethod
    def action(self):
        pass


# ---------------------------- options page state -------------------------


class OptionsPage(Page):

    def __init__(self, installer_wnd: InstallerWindow):
        Page.__init__(self, installer_wnd, index=0, title='Select Options:', action_btn_label='Install')

    def action(self):
        ProgressPage(self.installer_window)\
            .set_installer_options({
                'firefox': self.installer_window.optionFirefox.isChecked(),
                'foxyproxy': self.installer_window.optionFoxyProxy.isChecked()
            })\
            .set_page()


# ---------------------------- progress page state -------------------------


class ProgressPage(Page):
    log_signal = QtCore.pyqtSignal(str, name='msg')
    progress_signal = QtCore.pyqtSignal(int, name='percent')
    __installer_worker_thread = None
    __installer_workflow = None
    __installer_options = None
    __last_received_log = []

    def __init__(self, installer_wnd: InstallerWindow):
        Page.__init__(self, installer_wnd, index=1, title='Installing..', action_btn_label='Cancel')
        self.log_signal.connect(self.__log_listener)
        self.progress_signal.connect(self.__progress_listener)

    def set_installer_options(self, installer_opts):
        self.__installer_options = installer_opts
        return self

    def __log_listener(self, msg):
        # if current + previous log starts with "Progress:" -> replace last line
        reporting_download_progress = len(self.__last_received_log) > 0 and self.__last_received_log[-1].startswith('PROGRESS:') and msg.startswith('PROGRESS:')
        if len(self.__last_received_log) > 0 and reporting_download_progress:
            self.__last_received_log[-1] = msg
        else:
            self.__last_received_log.append(msg)
        self.installer_window.progress_log.setText("\n".join(self.__last_received_log))
        self.installer_window.progress_log.verticalScrollBar().setValue(self.installer_window.progress_log.verticalScrollBar().maximum())

    def __progress_listener(self, percent):
        # pseudo-percent to report error
        if percent < 0:
            self.installer_window.action_btn.setText("Exit")
            return
        percent = min(percent, 100)
        self.installer_window.progress_bar.setValue(percent)
        self.installer_window.progress_bar_text.setText(f'{percent}% complete')
        if percent == 100:
            self.installer_window.action_btn.setText("Finish")

    def __start(self):
        with LogCapturer([logger, installer.logger, installertools.logger], self.log_signal):
            self.__installer_workflow = InstallerWorkflow(self.__installer_options)
            self.__installer_workflow.install(self.progress_signal)

    def post_activate(self):
        self.__installer_worker_thread = threading.Thread(target=self.__start, name='install-worker', daemon=False)
        self.__installer_worker_thread.start()

    def action(self):
        if self.installer_window.action_btn.text() == "Finish":
            PostInstallationPage(self.installer_window).set_page()
        elif self.installer_window.action_btn.text() == "Exit":
            sys.exit(0)
        elif self.__installer_worker_thread is not None and self.__installer_worker_thread.is_alive():
            self.__installer_workflow.cancel()


class LogCapturer(logging.Handler):
    def __init__(self, loggers, log_receiver):
        logging.Handler.__init__(self)
        self.log_receiver = log_receiver
        self.loggers = loggers

    def emit(self, record):
        self.log_receiver.emit(self.format(record))

    def __enter__(self):
        for lg in self.loggers:
            lg.addHandler(self)

    def __exit__(self, exc_type, exc_val, exc_tb):
        for lg in self.loggers:
            lg.removeHandler(self)


class InstallerWorkflow:
    __cancelled = False

    @staticmethod
    def empty():
        pass

    def __init__(self, install_options):
        self._option_firefox = install_options.get('firefox') is not None
        self._option_foxyproxy = install_options.get('foxyproxy') is not None
        self.steps = [
            # prepare
            installer.ensure_permissions,
            installer.ensure_kite_proxy_home_dirs,
            installer.ensure_nssm_is_downloaded,
            installer.stop_background_services,
            # download
            installer.ensure_mitmproxy_is_downloaded,
            installer.ensure_secureoperator_is_downloaded,
            installer.ensure_kiteproxy_mitm_script_is_downloaded,
            installer.ensure_firefox_installed if self._option_firefox else InstallerWorkflow.empty,
            installer.ensure_foxyproxy_is_downloaded if self._option_foxyproxy else InstallerWorkflow.empty,
            installer.ensure_ffaddcert_is_downloaded,
            # install
            installer.retry(installer.create_mitm_certificates, tries=2),
            installer.install_root_certificate_on_os,
            installer.install_background_services,
            installer.retry(installer.set_active_interface_dns, tries=3),
            installer.add_mitm_certificate_to_firefox,
            installer.add_foxyproxy_to_firefox if self._option_foxyproxy else InstallerWorkflow.empty
        ]
        self.weight = math.ceil(100 / len(self.steps))

    def cancel(self):
        self.__cancelled = True

    def is_cancelled(self):
        return self.__cancelled

    def install(self, progress_signal):
        try:
            for no, step in enumerate(self.steps):
                if self.is_cancelled():
                    raise InterruptedError()
                step(self.is_cancelled)
                progress_signal.emit((no + 1) * self.weight)
            logger.info('Successfully finished.')
        except InterruptedError:
            progress_signal.emit(-1)
            installer.logger.error('User aborted !')
        except:
            progress_signal.emit(-1)
            installer.logger.error('Install error !')
            exc_type, exc_value, exc_traceback = sys.exc_info()
            logger.error("\n".join(traceback.format_exception(exc_type, exc_value, exc_traceback)))


# ----------------------------- finish window ------------------------------

class PostInstallationPage(Page):

    def __init__(self, installer_wnd: InstallerWindow):
        Page.__init__(self, installer_wnd, index=2, title='Post Installation', action_btn_label='Exit')

    def post_activate(self):
        self.installer_window.foxyproxy_save_btn.clicked.connect(self.save_foxyproxy_settings)
        self.installer_window.foxyproxy_conf_link.linkActivated.connect(self.show_foxyproxy_help)
        
    def save_foxyproxy_settings(self):
        foxyproxy_settings_path, _ = QFileDialog.getSaveFileName(
            parent=self.installer_window,
            caption="Save FoxyProxy Configuration",
            directory=os.path.join(installertools.get_desktop_path(), "FoxyProxySettings"),
            filter="Json configuration file (*.json)"
        )
        if len(foxyproxy_settings_path) > 0:
            installertools.copy_file(os.path.join(installertools.current_directory(), 'resources/foxyproxy.json'), foxyproxy_settings_path)

    def show_foxyproxy_help(self):
        url = 'file:///' + installertools.current_directory().replace('\\','/') + '/resources/help/foxyproxy/index.html'
        webbrowser.open(url=url, new=2)
        
    def action(self):
        sys.exit(0)

# ---------------------------- application run -----------------------------

fix_pyinstaller_root()
if not is_root():
    windows_run_as_admin()
    sys.exit(0)
app = QApplication(sys.argv)
icon = QIcon(":/icon/appicon.png")
app.setWindowIcon(icon)
windows_correct_icon()
installer_window = InstallerWindow()
installer_window.show()
sys.exit(app.exec())
