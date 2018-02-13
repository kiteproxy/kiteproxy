import os
import threading

from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import QMainWindow, QFileDialog

import installer
from gui.mpage import MonitorPage
from gui.page import Page
from gui.utils import dye_log
from installer.constants import create_logger
from installer.constants import exitApp
from installer.workflow import signals_progress, signals_log, \
    install_workflow_parameter_option_firefox, install_workflow_parameter_option_switchyomega, \
    selected_workflow, progress_workflow_install, progress_workflow_uninstall, \
    InstallWorkflow, UninstallWorkflow
from videodialog import PlayerDialog

logger = create_logger(__name__)

# ---------------------------- what-to-do page state -------------------------


class WhatToDoPage(Page):

    def __init__(self, installer_wnd: QMainWindow):
        Page.__init__(self, installer_wnd, index=0, title='What do you want to do ?', action_btn_label='Install')

    def post_activate(self):
        self.installer_window.wtd_install_btn.clicked.connect(self.action)
        self.installer_window.wtd_uninstall_btn.clicked.connect(self.uninstall_action)
        self.installer_window.wtd_monitor_btn.clicked.connect(self.monitor_action)

    def uninstall_action(self):
        ProgressPage(self.installer_window).set_installer_workflow_params({
            selected_workflow: progress_workflow_uninstall,
            progress_workflow_uninstall: self.installer_window.wtd_uninstall_clearcache_chck.isChecked()
        }).set_page()

    def monitor_action(self):
        MonitorPage(self.installer_window).set_page()

    def action(self):
        FeaturesPage(self.installer_window).set_page()

# ---------------------------- features page state -------------------------


class FeaturesPage(Page):

    def __init__(self, installer_wnd: QMainWindow):
        Page.__init__(self, installer_wnd, index=1, title='Select Features:', action_btn_label='Install')

    def back_action(self):
        WhatToDoPage(self.installer_window).set_page()

    def action(self):
        ProgressPage(self.installer_window).set_installer_workflow_params({
            selected_workflow: progress_workflow_install,
            install_workflow_parameter_option_firefox: self.installer_window.optionFirefox.isChecked(),
            install_workflow_parameter_option_switchyomega: self.installer_window.optionSwitchyOmega.isChecked()
        }).set_page()

# ---------------------------- progress page state -------------------------


class ProgressPage(Page):
    workflow_signal = pyqtSignal(dict, name='msg')
    __installer_worker_thread = None
    __installer_workflow = None
    __installer_workflow_params = None
    __last_received_log = []

    def __init__(self, installer_wnd: QMainWindow):
        Page.__init__(self, installer_wnd, index=2, title='(Un)Installing..', action_btn_label='Cancel')
        self.workflow_signal.connect(self.__workflow_signal_handler)

    def set_installer_workflow_params(self, workflow_params):
        self.__installer_workflow_params = workflow_params
        return self

    def __workflow_signal_handler(self, msg):
        if signals_progress in msg:
            self.__progress_listener(msg[signals_progress])
        if signals_log in msg:
            self.__log_listener(msg[signals_log])

    def __log_listener(self, msg):
        # if current + previous log starts with "Progress:" -> replace last line
        reporting_download_progress = len(self.__last_received_log) > 0 and ('PROGRESS:' in self.__last_received_log[-1]) and ('PROGRESS:' in msg)
        if len(self.__last_received_log) > 0 and reporting_download_progress:
            self.__last_received_log[-1] = dye_log(msg)
        else:
            self.__last_received_log.append(dye_log(msg))
        self.installer_window.progress_log.setText("\n".join(self.__last_received_log))
        self.installer_window.progress_log.verticalScrollBar().setValue(self.installer_window.progress_log.verticalScrollBar().maximum())

    def __progress_listener(self, percent):
        # pseudo-percent to report error
        if percent < 0:
            self.installer_window.action_btn.setText("Exit")
            self.installer_window.setCloseEnabled(True)
            return
        self.installer_window.progress_bar.setValue(percent)
        self.installer_window.progress_bar_text.setText(f'{percent}% complete')
        if percent == 100:
            self.installer_window.action_btn.setText("Next")
            self.installer_window.setCloseEnabled(True)

    def __start(self):
        if self.__installer_workflow_params[selected_workflow] == progress_workflow_uninstall:
            self.__installer_workflow = UninstallWorkflow(self.__installer_workflow_params, self.workflow_signal)
        else:
            self.__installer_workflow = InstallWorkflow(self.__installer_workflow_params, self.workflow_signal)
        self.__installer_workflow.run()

    def post_activate(self):
        self.installer_window.setCloseEnabled(False)
        self.__installer_worker_thread = threading.Thread(target=self.__start, name='install-worker', daemon=False)
        self.__installer_worker_thread.start()

    def action(self):
        if self.installer_window.action_btn.text() == "Next":
            PostInstallationPage(self.installer_window).set_page()
        elif self.installer_window.action_btn.text() == "Exit":
            exitApp()
        elif self.__installer_worker_thread is not None and self.__installer_worker_thread.is_alive():
            self.__installer_workflow.cancel()


# ----------------------------- finish window ------------------------------


class PostInstallationPage(Page):

    def __init__(self, installer_wnd: QMainWindow):
        Page.__init__(self, installer_wnd, index=3, title='Post Installation',
                      action_btn_label='Finish', action2_btn_label='Monitor Now')

    def post_activate(self):
        self.installer_window.switchyomega_save_btn.clicked.connect(self.save_foxyproxy_settings)
        self.installer_window.switchyomega_conf_link.linkActivated.connect(self.show_foxyproxy_help)
        
    def save_foxyproxy_settings(self):
        switchyomega_settings_path, _ = QFileDialog.getSaveFileName(
            parent=self.installer_window,
            caption="Save SwitchyOmega Configuration",
            directory=os.path.join(installer.utils.get_desktop_path(), "KiteProxy_SwitchyOmega.bak"),
            filter="SwitchyOmega configuration file (*.bak)"
        )
        if len(switchyomega_settings_path) > 0:
            installer.utils.copy_file(os.path.join(installer.utils.current_directory(), 'resources/OmegaOptions.bak'),
                                      switchyomega_settings_path)

    def show_foxyproxy_help(self):
        PlayerDialog(video='resources/firefox-post.mp4', dimensions=(838, 480), parent=self.installer_window).show()

    def back_action(self):
        MonitorPage(self.installer_window).set_page()

    def action(self):
        exitApp()