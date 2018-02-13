import threading
import re

from PyQt5.QtCore import pyqtSignal
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import QMainWindow, QLabel

from gui.utils import dye_log
from installer.constants import exitApp
from installer.workflow import MonitorWorkflow
from installer.mtasks import \
    signals_log, signals_progress, signals_dns, signals_sni, signals_tor, \
    DnsState, TorState, SniState, \
    signals_dns_sni_tor__state, signals_dns_sni_tor__params, signals_dns_sni_tor__failed, StateTools
from gui.page import Page


class MonitorPage(Page):
    workflow_signal = pyqtSignal(dict, name='msg')

    def __init__(self, installer_wnd: QMainWindow):
        super().__init__(installer_wnd, index=4, title='Proxy Monitor', action_btn_label='Exit', action2_btn_label='Report')
        self._images = {
            'error': QPixmap(':/monitor/error.svg'),
            'ok':    QPixmap(':/monitor/ok.svg'),
            'wait':  QPixmap(':/monitor/loading.svg')
        }
        self._name_to_all_states = {
            signals_dns: DnsState.All,
            signals_sni: SniState.All,
            signals_tor: TorState.All
        }
        self._component_elements = {
            signals_dns: {
                'icon': installer_wnd.subsystem_dns_icon,
                'label': installer_wnd.subsystem_dns_state
            },
            signals_sni: {
                'icon': installer_wnd.subsystem_sni_icon,
                'label': installer_wnd.subsystem_sni_state
            },
            signals_tor: {
                'icon': installer_wnd.subsystem_tor_icon,
                'label': installer_wnd.subsystem_tor_state
            }
        }
        self.workflow_signal.connect(self._workflow_signal_handler)
        self.__installer_workflow_params = {}
        self.__installer_workflow = None
        self.__installer_worker_thread = None

    def _start_check(self):
        if self.__installer_workflow is None:
            self.__installer_workflow = MonitorWorkflow(self.__installer_workflow_params, self.workflow_signal)
            self.installer_window.action_btn.setText("Stop")
            self.__installer_workflow.run()
            self.__installer_workflow = None
            self.installer_window.action_btn.setText("Recheck")

    def start_check_async(self):
        self.__installer_worker_thread = threading.Thread(target=self._start_check, name='monitor-worker', daemon=False)
        self.__installer_worker_thread.start()

    def _workflow_signal_handler(self, msg):
        if signals_log in msg:
            self._change_overall_status(msg[signals_log])
        elif signals_progress in msg:
            pass
        else:
            for element in self._name_to_all_states.keys():
                if element in msg:
                    all_states = self._name_to_all_states[element]
                    state = msg[element][signals_dns_sni_tor__state]
                    is_failed = msg[element][signals_dns_sni_tor__failed]
                    parameters = msg[element][signals_dns_sni_tor__params]
                    calculated_msg, calculated_icon = StateTools.calculate_message_and_icon(all_states, state, is_failed, parameters)
                    self._change_component_status(element, calculated_icon, calculated_msg)
                    break

    def _change_overall_status(self, status):
        if not status.startswith('DEBUG'):
            self.installer_window.monitor_overall_lbl.setText(dye_log(status, remove_level=True))

    def _change_component_status(self, element, icon, label):
        self._component_elements[element]['icon'].setPixmap(self._images[icon])
        self._component_elements[element]['label'].setText(label)

    def post_activate(self):
        self.start_check_async()

    def action(self):
        if self.__installer_workflow:
            self.__installer_workflow.cancel()
        else:
            self.start_check_async()

    def back_action(self):
        pass
