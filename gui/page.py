from abc import *

from PyQt5.QtCore import QObject
from PyQt5.QtWidgets import QMainWindow


_side_step_active_style = \
    'font-weight: bold;\ncolor: white;  \n padding: 12px 20px;\n margin: 5px 0;\nbackground: #747474;'
_side_step_inactive_style = \
    'font-weight: 500; \ncolor: #a2a2a2;\n padding:  8px 20px;\n'

# ---------------------------- options page state -------------------------


class Page(QObject):
    installer_window: QMainWindow

    def __init__(self, installer_wnd: QMainWindow, index: int, title: str, action_btn_label: str, action2_btn_label: str = ''):
        QObject.__init__(self)
        self.installer_window = installer_wnd
        self.index = index
        self.title = title
        self.action_btn_label = action_btn_label
        self.action2_btn_label = action2_btn_label

    def set_page(self):
        self.installer_window.page = self
        self._activate()

    def _activate(self):
        self.installer_window.stackedWidget.setCurrentIndex(self.index)
        side_steps = [
            self.installer_window.side_step0,
            self.installer_window.side_step1,
            self.installer_window.side_step2,
            self.installer_window.side_step3,
            self.installer_window.side_step4,
        ]
        for idx, side_step in enumerate(side_steps):
            side_step.setStyleSheet(_side_step_active_style if idx == self.index else _side_step_inactive_style)
        self.installer_window.title.setText(self.title)
        self.installer_window.action_btn.setText(self.action_btn_label)
        self.installer_window.action_btn2.setText(self.action2_btn_label)
        self.installer_window.action_btn2.setVisible(bool(self.action2_btn_label))
        self.post_activate()

    def is_busy(self):
        return False

    def is_selectable(self):
        return True

    def post_activate(self):
        pass

    @abstractmethod
    def back_action(self):
        pass

    def action(self):
        pass
