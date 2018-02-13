import installer
import sys
from PyQt5.QtGui import QIcon
from installer.constants import is_win, exitApp
from PyQt5 import uic
from gui import resources_rc
from gui.ipages import FeaturesPage, WhatToDoPage, MonitorPage, ProgressPage
from gui import utils as guiutils
from installer.utils import fix_pyinstaller_root, windows_correct_icon
from PyQt5.QtWidgets import QApplication, QMainWindow
from PyQt5 import QtCore

from installer.workflow import *


class InstallerWindow(QMainWindow):

    def __init__(self):
        QMainWindow.__init__(self)
        uic.loadUi('resources/window.ui', self)
        self.action_btn.clicked.connect(self.action_button_click)
        self.action_btn2.clicked.connect(self.backaction_button_click)
        self.prevent_close = False
        # FeaturesPage(self).set_page()
        # MonitorPage(self).set_page()
        WhatToDoPage(self).set_page()

    def setCloseEnabled(self, enabled):
        if enabled:
            self.setWindowFlags(self.windowFlags() | QtCore.Qt.WindowCloseButtonHint)
        else:
            self.setWindowFlags(self.windowFlags() & ~QtCore.Qt.WindowCloseButtonHint)
        self.show()
        self.activateWindow()

    def action_button_click(self):
        self.page.action()

    def backaction_button_click(self):
        self.page.back_action()

# ---------------------------- application run -----------------------------


fix_pyinstaller_root()
if not installer.utils.is_root() and is_win:
    installer.utils.windows_run_as_admin()
    sys.exit(0)
app = QApplication(sys.argv)
icon = QIcon(":/icon/appicon.png")
app.setWindowIcon(icon)
windows_correct_icon()
guiutils.add_san_francisco_fonts()
installer_window = InstallerWindow()
installer_window.show()
exitApp(app.exec())
