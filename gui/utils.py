from PyQt5.QtGui import QFontDatabase
import re

log_prefix = re.compile("^((DEBUG   )|(INFO    )|(WARNING )|(ERROR   ))")


def add_san_francisco_fonts():
    fonts = [
        ':fonts/fonts/SF-Pro-Display-Regular.ttf',
        ':fonts/fonts/SF-Pro-Display-Medium.ttf',
        ':fonts/fonts/SF-Pro-Display-Bold.ttf'
    ]
    for font in fonts:
        font_db = QFontDatabase()
        font_db.addApplicationFont(font)


def dye_log(log, remove_level=False):
    trimmed_log = log if not remove_level else re.sub(log_prefix, '', log)
    if str.startswith(log, "DEBUG"):
        return f"<font color=\"grey\">{trimmed_log}</font><br/>"
    elif str.startswith(log, "WARNING"):
        return f"<font color=\"orange\">{trimmed_log}</font><br/>"
    elif str.startswith(log, "ERROR"):
        return f"<font color=\"red\">{trimmed_log}</font><br/>"
    else:
        return f"{trimmed_log}<br/>"
