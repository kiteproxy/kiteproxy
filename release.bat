del /Q /s __pycache__
del /Q /s dist
del /Q /s build
rd  /Q /s __pycache__
rd  /Q /s dist
rd  /Q /s build
pyinstaller ^
--windowed ^
--icon resources/appicon.ico ^
--name setup ^
--paths "C:\Program Files (x86)\Windows Kits\10\Redist\ucrt\DLLs\x64" ^
--add-data resources/foxyproxy.json;resources ^
--add-data resources/*.ui;resources ^
--add-data resources/help;resources/help ^
gui.py
ren .\dist\setup kiteproxy