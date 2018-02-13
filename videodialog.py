from PyQt5 import QtCore
from PyQt5 import uic
from PyQt5.QtCore import QUrl
from PyQt5.QtMultimedia import QMediaPlayer, QMediaContent
from PyQt5.QtMultimediaWidgets import QVideoWidget
from PyQt5.QtWidgets import QDialog, QStyle, QSlider

from installer.constants import create_logger

logger = create_logger(__name__)


class PlayerDialog(QDialog):
    def __init__(self, video, dimensions, parent=None):
        QDialog.__init__(self, parent=parent, flags=QtCore.Qt.WindowSystemMenuHint | QtCore.Qt.WindowTitleHint | QtCore.Qt.WindowCloseButtonHint)
        uic.loadUi('resources/videoplay.ui', self)
        self.videoWidget = QVideoWidget()
        self.stageLayout.addWidget(self.videoWidget)
        self.stage.setMinimumSize(QtCore.QSize(dimensions[0], dimensions[1]))
        self.playbtn.setIcon(self.style().standardIcon(QStyle.SP_MediaPlay))
        self.seekslider.mousePressEvent = self.__direct_slider_click
        self.seekslider.sliderMoved.connect(self.set_position)
        self.mediaPlayer = QMediaPlayer(None, QMediaPlayer.VideoSurface)
        self.mediaPlayer.setVideoOutput(self.videoWidget)
        self.mediaPlayer.stateChanged.connect(self.__media_state_changed)
        self.mediaPlayer.positionChanged.connect(self.__position_changed)
        self.mediaPlayer.durationChanged.connect(self.__duration_changed)
        self.mediaPlayer.error.connect(self.handle_error)
        self.mediaPlayer.setMedia(QMediaContent(QUrl.fromLocalFile(video)))

    def __media_state_changed(self, state):
        if state == QMediaPlayer.PlayingState:
            self.playbtn.setIcon(self.style().standardIcon(QStyle.SP_MediaPause))
        else:
            self.playbtn.setIcon(self.style().standardIcon(QStyle.SP_MediaPlay))
        if state == QMediaPlayer.StoppedState:
            self.play()

    def __direct_slider_click(self, event):
        if event.button() == QtCore.Qt.LeftButton:
            calc_value = self.seekslider.minimum() + ((self.seekslider.maximum() - self.seekslider.minimum()) * event.x()) / self.seekslider.width()
            self.seekslider.setValue(calc_value)
            self.set_position(calc_value)
            event.accept()
        QSlider.mousePressEvent(self.seekslider, event)

    def __position_changed(self, position):
        self.seekslider.setValue(position)

    def __duration_changed(self, duration):
        self.seekslider.setRange(0, duration)
        self.play()

    def handle_error(self):
        logger.error(self.mediaPlayer.errorString())

    def play(self):
        if self.mediaPlayer.state() == QMediaPlayer.PlayingState:
            self.mediaPlayer.pause()
        else:
            self.mediaPlayer.play()

    def set_position(self, position):
        self.mediaPlayer.setPosition(position)
