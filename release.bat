del /Q /s __pycache__
del /Q /s dist
del /Q /s build
rd  /Q /s __pycache__
rd  /Q /s dist
rd  /Q /s build
call .\venv\Scripts\activate.bat
pyinstaller ^
--icon resources/appicon.ico ^
--name setup ^
--windowed ^
--uac-admin ^
--paths "C:\Program Files (x86)\Windows Kits\10\Redist\ucrt\DLLs\x86" ^
--add-data resources/*.bak;resources ^
--add-data resources/*.ui;resources ^
--add-data resources/*.mp4;resources ^
--add-data resources/nssm.exe;resources ^
main.py
call deactivate.bat
ren .\dist\setup kiteproxy