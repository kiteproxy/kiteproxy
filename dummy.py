import os
from installer import base as installerbase
from installer import itasks, mtasks
from glob import glob
import platform
from pathlib import Path
from installer import utils
# from installer.mtasks import *
from installer.itasks import Fetch7z, FetchTor, CreateAutoStartServices

# counter = 0
#
# def three_second_timeout():
#     global counter
#     counter += 1
#     if counter >= 3:
#         return True
#     time.sleep(1)
#     return False
#
# run('ping -n 10 4.2.2.4', three_second_timeout)

# requests.get(
#     'http://'
#     headers=headers,
#     verify=False
# )
# try:

# except:
#     pass
from installer.itasks import StopKiteProxyServices, EnsureFirefoxIsClosed, RemoveAllFilesExceptMe

# EnsureFirefoxIsClosed().run()

# p = installerbase.ProcessRunTask('ping -n 4 4.2.2.4')
# exit_code, std_out, std_err = p.run()
#
# print(f'exit code: {exit_code}')
# print(f'standard out: {std_out}')
# print(f'standard error: {std_err}')

# task = RemoveAllFilesExceptMe()
# task.set_parameters({'clear_cache': False})
# task.run()

# CheckSNIHiding().run()
# Fetch7z().run()

# StopKiteProxyServices().run()
# CreateAutoStartServices().run()

# itasks.FetchSwitchyOmega().run()
# itasks.FetchHttpsEverywhere().run()
# itasks.AddFirefoxAddons().run()
# itasks.FetchNSSM().run()

# mtasks.CheckTor().run()

# itasks.RemoveRootCertificatesFromOS().run()
# itasks.IsCertificateInstalledOnFirefox().run()
# itasks.InstallRootCertificatesToWindows().run()
# print(itasks.GetRootCertificatesFromWindows().run())
# print(itasks.GetRootCertificatesFromWindows().run())
# print(itasks.RemoveCertificateFromFirefox().run())