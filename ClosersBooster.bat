@echo off
Title ClosersBooster Finalizando Procesos Innecesarios(By Henry)
MODE con:cols=76 lines=20
color 0E
cls
:: BatchGotAdmin 
:------------------------------------- 
REM --> Check for permissions 
    IF "%PROCESSOR_ARCHITECTURE%" EQU "amd64" (
>nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\SysWOW64\config\system" 
) ELSE (
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system" 
) 

REM --> If error flag set, we do not have admin. 
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges... 
    goto UACPrompt 
) else (goto gotAdmin) 

:UACPrompt 
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs" 
    set params=%* 
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0"" %params:"=""%", "", "runas", 1 >> "%temp%\getadmin.vbs" 

    "%temp%\getadmin.vbs" 
    del "%temp%\getadmin.vbs" 
    exit /B 

:gotAdmin 
    pushd "%CD%" 
    CD /D "%~dp0" 
:--------------------------------------  

:INICIO
Set Linea=----------------------------------------------------------------------------
cls
echo %linea%
echo  [A] Closers, Discord, Steam y Navegadores "ABIERTO" (lo demas cierralo)
echo  [C] Cerrar Todo Menos Closers (Modo Nomal)
echo  [S] Cerrar Todo Menos Closers !!Modo Extremo!!
echo  [D] Cerrar Todo Menos Closers y Discord
echo  [G] Cerrar Todo Menos Closers y Google Chrome
echo  [F] Cerrar Todo Menos Closers y Firefox
echo %linea%
Echo  [X] Reactivar servicio de Impresoras
echo %linea%
Echo  [U] Desactivar Actualizaciones(Win-Update, Adobe, Google, Java..)
echo %linea%
echo  NOTA: Se te recomienda que guardes todo tu trabajo en Microsoft Office, 
echo  Navegadores, etc.. antes de ejecutar esta Herramienta, para que no 
echo  pierdas el trabajo realizado.
echo %linea%

:Validar
SET /p var= ^> Seleccione una opcion [...]: 
IF /I "%var%"=="A" call :Todos
IF /I "%var%"=="C" call :Closers
IF /I "%var%"=="S" call :ClosersEX
IF /I "%var%"=="D" call :Discord
IF /I "%var%"=="G" call :Google
IF /I "%var%"=="F" call :Firefox
IF /I "%var%"=="X" call :Impresora
IF /I "%var%"=="U" call :OptimizarOK
SET "var="
Goto INICIO

:Todos
CLS
Goto Generico

:Closers
CLS
taskkill /f /t /im Chrome.exe
taskkill /f /t /im Discord.exe
taskkill /f /t /im Firefox.exe
Goto Generico

:ClosersEX
CLS
taskkill /f /t /im Chrome.exe
taskkill /f /t /im Discord.exe
taskkill /f /t /im Firefox.exe
taskkill /f /t /im Calc.exe
taskkill /f /t /im NOTEPAD.exe
taskkill /f /t /im Taskmgr.exe
taskkill /f /t /im Wale.exe
taskkill /f /t /im mpc-hc64.exe
taskkill /f /t /im wmplayer.exe
del "C:\closers\Log" /f /s /q
del "C:\Program Files (x86)\Steam\steamapps\common\closers\Log" /f /s /q
rd "C:\closers\Log" /s /q
rd "C:\Program Files (x86)\Steam\steamapps\common\closers\Log" /s /q
del %WINDIR%\Temp /f /s /q
rd %WINDIR%\Temp /s /q
MKDIR %WINDIR%\Temp
IF EXIST %temp% (
cd /D %temp%
for /d %%D in (*) do rd /s /q "%%D"
del /f /q *
)
taskkill /f /im Explorer.exe
Start Explorer.exe
Goto Generico

:Discord
CLS
taskkill /f /t /im Chrome.exe
taskkill /f /t /im Firefox.exe
Goto Generico

:Google
CLS
taskkill /f /t /im Discord.exe
taskkill /f /t /im Firefox.exe
Goto Generico

:Firefox
CLS
taskkill /f /t /im Chrome.exe
taskkill /f /t /im Discord.exe
Goto Generico

:Impresora
CLS
sc start Spooler
Echo Servioio de impresion activado correctamente, pulsa una tecla para salir.
PAUSE > NUL
EXIT

:Generico
wmic process where name="cw.exe" CALL setpriority 256
for /f "tokens=2 delims=()" %%x in ('sc query state^=all ^| findstr Google ^| findstr Update') do sc stop %%x
for /f "tokens=2 delims=()" %%x in ('sc query state^=all ^| findstr Adobe ^| findstr Update') do sc stop %%x
sc stop AdobeARMservice
sc stop DHCPServer
sc stop MozillaMaintenance
sc stop Spooler
sc stop VBoxSDS
sc stop cmcore
sc stop gupdate
sc stop gupdatem
sc stop iphlpsvc
sc stop teamviewer
sc stop wlidsvc
sc stop wuauserv
taskkill /f /t /im AcroRd32.exe
taskkill /f /t /im CCUpdate.exe
taskkill /f /t /im CCleaner.exe
taskkill /f /t /im CCleaner64.exe
taskkill /f /t /im crashreporter.exe
taskkill /f /t /im Dropbox.exe
taskkill /f /t /im ETDCtrl.exe
taskkill /f /t /im ETDCtrlHelper.exe
taskkill /f /t /im ETDService.exe
taskkill /f /t /im GoogleCrashHandler.exe
taskkill /f /t /im GoogleCrashHandler64.exe
taskkill /f /t /im GoogleUpdate.exe
taskkill /f /t /im Ielowutil.exe
taskkill /f /t /im Iexplore.exe
taskkill /f /t /im Igfxpers.exe
taskkill /f /t /im Igfxtray.exe
taskkill /f /t /im MSACCESS.exe
taskkill /f /t /im MSOSYNC.exe
taskkill /f /t /im OneDrive.exe
taskkill /f /t /im Photoshop.exe
taskkill /f /t /im POWERPNT.exe
taskkill /f /t /im SndVol.exe 
taskkill /f /t /im SystemPropertiesAdvanced.exe
taskkill /f /t /im SystemSettings.exe
taskkill /f /t /im SystemSettingsBroker.exe
taskkill /f /t /im TeamViewer.exe
taskkill /f /t /im thunderbird.exe
taskkill /f /t /im UninstallMonitor.exe
taskkill /f /t /im VBoxSDS.exe
taskkill /f /t /im VBoxSVC.exe
taskkill /f /t /im VirtualBox.exe
taskkill /f /t /im cmcore.exe
taskkill /f /t /im excel.exe
taskkill /f /t /im iTunes.exe
taskkill /f /t /im iTunesHelper.exe
taskkill /f /t /im infopath.exe
taskkill /f /t /im jucheck.exe
taskkill /f /t /im juscheck.exe
taskkill /f /t /im mspub.exe
taskkill /f /t /im onenote.exe
taskkill /f /t /im outlook.exe
taskkill /f /t /im RAVBg64.exe
taskkill /f /t /im ShellExperienceHost.exe
taskkill /f /t /im systeminfo.exe
taskkill /f /t /im WinAuth.exe
taskkill /f /t /im winword.exe
Call :LiberarRam
EXIT

Rem Nuevas Funciones

:OptimizarOK
CLS
CALL :UPDATESWINOFF
CALL :FirefoxPrefOFF
CALL :FirefoxSET
CALL :AdobeGoogleUpdateOFF
CALL :MemoryOptimize
Goto INICIO

:UPDATESWINOFF
CLS
ECHO Se estan deshabilitando las actualizaciones de Windows...
sc stop wuauserv >NUL 2>&1
sc config wuauserv start=disabled >NUL 2>&1
SET "z1=HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization"
reg add "%z1%" /v SystemSettingsDownloadMode /d 0 /t REG_DWORD /f
reg add "%z1%\Config" /v DODownloadMode /d 0 /t REG_DWORD /f
reg add "%z1%\Config" /v DownloadMode /d 0 /t REG_DWORD /f
SET "z2=HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
reg add %z2% /v AUOptions /d 4 /t REG_DWORD /f
reg add %z2% /v NoAutoUpdate /d 1 /t REG_DWORD /f
SET "z3=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade"
reg add %z3% /v "AllowOSUpgrade" /t REG_DWORD /d 0 /f
reg add %z3% /v "ReservationsAllowed" /t REG_DWORD /d 0 /f
Rem Otros Desactivadores
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v AutoDownload /d 2 /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /d 2 /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v AutoDownload /d 2 /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v DeferUpgrade /d 1 /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableOSUpgrade" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Gwx" /v "DisableGwx" /t REG_DWORD /d 1 /f
CLS
ECHO  * ACTUALIZACIONES DE WINDOWS DESACTIVADAS - PRESIONA ENTER *
ECHO.
ECHO.
GOTO:EOF

:FirefoxPrefOFF
SET "z1=%ProgramFiles%\Mozilla Firefox"
SET "z2=%PROGRAMFILES(x86)%\Mozilla Firefox"
SET "z3=defaults\pref"
SET "z4="
SET "z5="
IF EXIST "%z1%" SET "z4=%z1%\%z3%" & SET "z5=%z1%" & Call :FirefoxSET
IF EXIST "%z2%" SET "z4=%z2%\%z3%" & SET "z5=%z1%" & Call :FirefoxSET
GOTO:EOF

:FirefoxSET
IF Exist "%z4%" Rd /S /Q "%z4%" >NUL	
IF Not Exist "%z4%" MkDir "%z4%" >NUL	
echo // > "%z4%\local-settings.js"
echo pref^("general.config.filename", "mozilla.cfg"^); >> "%z4%\local-settings.js" 
echo pref^("general.config.obscure_value", 0^); >> "%z4%\local-settings.js" 
echo pref^("browser.rights.3.shown", true^); >> "%z4%\local-settings.js" 
echo // > "%z5%\mozilla.cfg"
echo lockPref^("app.update.service.enabled", false^); >> "%z5%\mozilla.cfg"
echo lockPref^("app.update.url", "https://localhost"^); >> "%z5%\mozilla.cfg"
GOTO:EOF

:AdobeGoogleUpdateOFF
CLS
Rem Desactivar configuracion Servicios de Google y Adobe
for /f "tokens=2 delims=()" %%x in ('sc query state^=all ^| findstr Google ^| findstr Update') do sc config %%x start=disabled
for /f "tokens=2 delims=()" %%x in ('sc query state^=all ^| findstr Adobe ^| findstr Update') do sc config %%x start=disabled
Rem Desactivar Tareas de Google y Adobe
for /f "tokens=2 delims=\" %%x in ('schtasks /query /fo:list ^| findstr ^^Google ^| findstr ^^Update') do schtasks /Change /TN "%%x" /Disable
for /f "tokens=2 delims=\" %%x in ('schtasks /query /fo:list ^| findstr ^^Adobe ^| findstr ^^Update') do schtasks /Change /TN "%%x" /Disable
Rem Deteniendo Servicios de Google y Adobe
for /f "tokens=2 delims=()" %%x in ('sc query state^=all ^| findstr Google ^| findstr Update') do sc stop %%x
for /f "tokens=2 delims=()" %%x in ('sc query state^=all ^| findstr Adobe ^| findstr Update') do sc stop %%x
sc config AdobeARMservice start= disabled
sc stop AdobeARMservice
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SunJavaUpdateSched" /f >NUL 2>&1
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" /v "SunJavaUpdateSched" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\JavaSoft\Java Update\Policy" /V EnableJavaUpdate /T REG_DWORD /D 0 /F >NUL 2>&1
reg add "HKLM\SOFTWARE\Wow6432Node\JavaSoft\Java Update\Policy" /V EnableJavaUpdate /T REG_DWORD /D 0 /F >NUL 2>&1
taskkill /IM jucheck.exe /F
taskkill /IM juscheck.exe /F
CLS
ECHO  * SE HAN DESACTIVADO CORRECTAMENTE LAS ACTUALIZACIONES - PRESIONA ENTER *
ECHO.
ECHO.
GOTO:EOF

:MemoryOptimize
CLS
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "AlwaysUnloadDll" /t REG_DWORD /d "1" /f
rem Powershell.exe Disable-MMAgent -MemoryCompression
Powershell.exe Enable-MMAgent -MemoryCompression
GOTO:EOF

:LiberarRam
cls
echo.
set /p= " Liberando RAM, por favor espere...  " <nul  
timeout /t 2 /nobreak > NUL
echo Mystring=(80000000) > %temp%\liberaram.vbs
echo Mystring=(160000000) >> %temp%\liberaram.vbs
echo Mystring=(320000000) >> %temp%\liberaram.vbs
echo Mystring=(655000000) >> %temp%\liberaram.vbs
echo Mystring=(1000000000) >> %temp%\liberaram.vbs
echo Mystring=(1655000000) >> %temp%\liberaram.vbs
echo Mystring=(2000000000) >> %temp%\liberaram.vbs
echo Mystring=(2650000000) >> %temp%\liberaram.vbs
echo Mystring=(3000000000) >> %temp%\liberaram.vbs
start %temp%\liberaram.vbs
CLS
echo  RAM liberada.. [OK] 
timeout /t 3 /nobreak > NUL
Del /S /Q %temp%\liberaram.vbs
GOTO:EOF
