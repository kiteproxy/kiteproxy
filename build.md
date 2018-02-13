Build
=============================================

1. Run `.\uicompile.bat` to re-make `resources_rc.py` from `resources/resources.qrc`.
2. Run `.\release.bat`

Fix Pyinstaller warning + windows7 problem
---------------------------------------------
1. To fix Windows7 problem download `Windows 10 SDK` from [here](https://go.microsoft.com/fwlink/?linkid=864422)
2. Check and install only `Windows SDK for Desktop C++ x86 Apps`.
3. Add 

Fix mitmdump problem in windows7
=============================================

Build mitmdump in a non __onefile__ fashion from source :

1. Check out mitmproxy source using `git clone --depth 1 "https://github.com/mitmproxy/mitmproxy.git"`
2. Open up a PowerShell as administrator
3. Disable execution policies using `Set-ExecutionPolicy Bypass -Scope LocalMachine`
4. Run `.\dev.ps1` to get in an isolated python environment and retrieve all dependencies
5. Install `pip install pyinstaller pypiwin32` within the environment
6. Make two modifications on `.\release\rtool.py` before running it:
   1. Find this around line 65-70 and change it
    
      ```
      BDISTS = {
          "mitmproxy": ["mitmproxy", "mitmdump", "mitmweb"],
          "pathod": ["pathoc", "pathod"]
      }
      ``` 
      to:
      ```
      BDISTS = {
          "mitmproxy": ["mitmdump"]
      }
      ```
   2. Find this around line 235 and remove `"--onefile",` parameter
    
      ```
         subprocess.check_call(
             [
                 "pyinstaller",
                 "--clean",
                 "--workpath", PYINSTALLER_TEMP,
                 "--distpath", PYINSTALLER_DIST,
                 "--additional-hooks-dir", PYINSTALLER_HOOKS,
                 "--onefile",
                 "--console",
                 "--icon", "icon.ico",
                 # This is PyInstaller, so setting a
                 # different log level obviously breaks it :-)
                 # "--log-level", "WARN",
             ]
      ```
     3. Remove these lines 68-70
         ```
        if platform.system() == "Windows":
           BDISTS["mitmproxy"].remove("mitmproxy")
           
         ```
     4. And change this at line 248
      
        ```
          executable += ".exe"
        ``` 
        to:
        ```
          executable += "\\" + tool + ".exe"
        ```