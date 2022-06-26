@echo off
Title ClosersBooster Finalizando Procesos Innecesarios(By Henry)
MODE con:cols=76 lines=23
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

:MisVariables
CLS
CD /D "%~dp0"
SET "MYCLOSERS=C:\closers"
IF EXIST "%PROGRAMFILES(X86)%\Steam\steamapps\common\closers\CLOSERS.EXE" (
SET "MYCLOSERS=%PROGRAMFILES(X86)%\Steam\steamapps\common\closers")
for /f "tokens=1,2,* " %%i in ('REG QUERY HKEY_CURRENT_USER\Software\FTweak\RAMRush /v programfile ^| find /i "programfile"') do set "regramrush=%%k"

:INICIO
Set Linea=----------------------------------------------------------------------------
CLS
SET "ClosersAPP=0"
SET "Navegador=el Navegador"
SET "ERRORLEVEL="
tasklist /fi "IMAGENAME eq Steam.exe" | find /I "Steam.exe"
IF "%ERRORLEVEL%"=="0" SET "Navegador=Steam"
SET "ERRORLEVEL="
tasklist /fi "IMAGENAME eq CLOSERS.EXE" | find /I "CLOSERS.EXE"
IF "%ERRORLEVEL%"=="0" ( SET "ClosersAPP=0"
CLS
echo %linea%
echo  Selecciona una opcion y Pulsa el Boton Amarillo de PLAY en el Launcher:
GOTO INICIO2 )
SET "ERRORLEVEL="
tasklist /fi "IMAGENAME eq CW.EXE" | find /I "CW.EXE"
IF "%ERRORLEVEL%"=="1" ( SET "ClosersAPP=1"
CLS
echo %linea%
echo  Selecciona una opcion y luego abre Closers por %Navegador%:
GOTO INICIO2 )
CLS
:INICIO2
echo %linea%
echo  [A] Closers, Discord, Steam y Navegadores "ABIERTO" (lo demas cierralo)
echo  [C] Cerrar Todo Menos Closers (Modo Nomal)
echo  [E] Cerrar Todo Menos Closers !!Modo Extremo!!
echo  [D] Cerrar Todo Menos Closers y Discord
echo  [G] Cerrar Todo Menos Closers y Google Chrome(y Brave)
echo  [F] Cerrar Todo Menos Closers y Firefox
echo  [M] Cerrar Todo Menos Closers y Microsoft Edge
echo  [O] Cerrar Todo Menos Closers y Opera(y Safari)
echo %linea%
Echo  [X] Reactivar servicio de Impresoras y Sysmain(Superfetch)
echo %linea%
Echo  [U] Desactivar Actualizaciones(Win-Update, Adobe, Google, Java..)
echo %linea%
echo  NOTA: Se te recomienda que guardes todo tu trabajo en Microsoft Office, 
echo  Navegadores, etc.. antes de ejecutar esta Herramienta, para que no 
echo  pierdas el trabajo realizado.
echo %linea%

:Validar
SET /p var= ^> Seleccione una opcion [...]: 
IF /I "%var%"=="A" Goto Todos
IF /I "%var%"=="C" Goto Closers
IF /I "%var%"=="E" Goto ClosersEX
IF /I "%var%"=="D" Goto Discord
IF /I "%var%"=="G" Goto Google
IF /I "%var%"=="F" Goto Firefox
IF /I "%var%"=="M" Goto MSEDge
IF /I "%var%"=="O" Goto Opera
IF /I "%var%"=="X" call :Impresora
IF /I "%var%"=="U" call :OptimizarOK
SET "var="
Goto INICIO

:Todos
IF "%ClosersAPP%"=="1" Call :ENMEMORIA
CLS
Goto Generico

:Closers
IF "%ClosersAPP%"=="1" Call :ENMEMORIA
CLS
taskkill /f /t /im Brave.exe
taskkill /f /t /im Chrome.exe
taskkill /f /t /im Discord.exe
taskkill /f /t /im Firefox.exe
taskkill /f /t /im MicrosoftEdgeCP.exe
taskkill /f /t /im Msedge.exe
taskkill /f /t /im Opera.exe
taskkill /f /t /im Safari.exe
taskkill /f /t /im StikyNot.exe
Goto Generico

:ClosersEX
IF "%ClosersAPP%"=="1" Call :ENMEMORIA
CLS
taskkill /f /t /im Brave.exe
taskkill /f /t /im Chrome.exe
taskkill /f /t /im Discord.exe
taskkill /f /t /im Firefox.exe
taskkill /f /t /im Calc.exe
taskkill /f /t /im MicrosoftEdgeCP.exe
taskkill /f /t /im Msedge.exe
taskkill /f /t /im NOTEPAD.exe
taskkill /f /t /im Opera.exe
taskkill /f /t /im Safari.exe
taskkill /f /t /im StikyNot.exe
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
IF "%ClosersAPP%"=="1" Call :ENMEMORIA
CLS
taskkill /f /t /im Brave.exe
taskkill /f /t /im Chrome.exe
taskkill /f /t /im Firefox.exe
taskkill /f /t /im MicrosoftEdgeCP.exe
taskkill /f /t /im Msedge.exe
taskkill /f /t /im Opera.exe
taskkill /f /t /im Safari.exe
Goto Generico

:Google
IF "%ClosersAPP%"=="1" Call :ENMEMORIA
CLS
taskkill /f /t /im Discord.exe
taskkill /f /t /im Firefox.exe
taskkill /f /t /im MicrosoftEdgeCP.exe
taskkill /f /t /im Msedge.exe
taskkill /f /t /im Opera.exe
taskkill /f /t /im Safari.exe
Goto Generico

:Firefox
IF "%ClosersAPP%"=="1" Call :ENMEMORIA
CLS
taskkill /f /t /im Brave.exe
taskkill /f /t /im Chrome.exe
taskkill /f /t /im Discord.exe
taskkill /f /t /im MicrosoftEdgeCP.exe
taskkill /f /t /im Msedge.exe
taskkill /f /t /im Opera.exe
taskkill /f /t /im Safari.exe
Goto Generico

:MSEDge
IF "%ClosersAPP%"=="1" Call :ENMEMORIA
CLS
taskkill /f /t /im Brave.exe
taskkill /f /t /im Chrome.exe
taskkill /f /t /im Discord.exe
taskkill /f /t /im Firefox.exe
taskkill /f /t /im Opera.exe
taskkill /f /t /im Safari.exe
Goto Generico

:Opera
IF "%ClosersAPP%"=="1" Call :ENMEMORIA
CLS
taskkill /f /t /im Brave.exe
taskkill /f /t /im Chrome.exe
taskkill /f /t /im Discord.exe
taskkill /f /t /im Firefox.exe
taskkill /f /t /im MicrosoftEdgeCP.exe
taskkill /f /t /im Msedge.exe
Goto Generico

:Impresora
CLS
sc start Spooler
sc start sysmain
CLS
Echo Servicio de impresion Y Sysmain activado correctamente, pulsa una tecla para salir.
PAUSE > NUL
EXIT

:Generico
for /f "tokens=2 delims=()" %%x in ('sc query state^=all ^| findstr Google ^| findstr Update') do sc stop %%x
for /f "tokens=2 delims=()" %%x in ('sc query state^=all ^| findstr Adobe ^| findstr Update') do sc stop %%x
sc stop "Adguard Service"
sc stop AdobeARMservice
sc stop DHCPServer
sc stop MozillaMaintenance
sc stop Spooler
sc stop VBoxSDS
sc stop cmcore
sc stop gupdate
sc stop gupdatem
sc stop iphlpsvc
sc stop sysmain
sc stop teamviewer
sc stop WSearch
sc stop wlidsvc
sc stop wuauserv
taskkill /t /f /im Adguard.exe 
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
taskkill /f /t /im RuntimeBroker.exe
taskkill /f /t /im ShellExperienceHost.exe
taskkill /f /t /im smartscreen.exe
taskkill /f /t /im systeminfo.exe
taskkill /f /t /im WinAuth.exe
taskkill /f /t /im winword.exe
CALL :OPTIMIZAR
CALL :RAMRush
EXIT

Rem Nuevas Funciones

:OptimizarOK
CLS
sc config WSearch start=disabled >NUL 2>&1
CALL :UPDATESWINOFF
CALL :FirefoxPrefOFF
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

:RAMRush
SET "MYWiseMemo=%PROGRAMFILES%\Wise\Wise Memory Optimizer\WiseMemoryOptimzer.exe"
IF EXIST "%PROGRAMFILES(X86)%\Wise\Wise Memory Optimizer\WiseMemoryOptimzer.exe" (
SET "MYWiseMemo=%PROGRAMFILES%\Wise\Wise Memory Optimizer\WiseMemoryOptimzer.exe")
IF EXIST "%~dp0WiseMemoryOptimzer.exe" (
SET "MYWiseMemo=%~dp0WiseMemoryOptimzer.exe")
IF EXIST "%MYWiseMemo%" (
taskkill /f /t /im RAMRush.exe
IF EXIST "%MYWiseMemo%" taskkill /f /t /im WiseMemoryOptimzer.exe
Echo ^[MemoryOptimizer^] > "%APPDATA%\Wise Memory Optimzer\MemoryConfig.ini"
Echo Language^=Spanish^(Spain^) >> "%APPDATA%\Wise Memory Optimzer\MemoryConfig.ini"
Echo AutoOpt^=1 >> "%APPDATA%\Wise Memory Optimzer\MemoryConfig.ini"
Echo AutoRun^=0 >> "%APPDATA%\Wise Memory Optimzer\MemoryConfig.ini"
Echo ClearBoard^=1 >> "%APPDATA%\Wise Memory Optimzer\MemoryConfig.ini"
Echo AutoUpdate^=0 >> "%APPDATA%\Wise Memory Optimzer\MemoryConfig.ini"
Echo DefragMem^=1 >> "%APPDATA%\Wise Memory Optimzer\MemoryConfig.ini"
Echo ClearMem^=1 >> "%APPDATA%\Wise Memory Optimzer\MemoryConfig.ini"
Echo ClearStandy^=0 >> "%APPDATA%\Wise Memory Optimzer\MemoryConfig.ini"
Echo Idle^=0 >> "%APPDATA%\Wise Memory Optimzer\MemoryConfig.ini"
Echo MinToTray^=1 >> "%APPDATA%\Wise Memory Optimzer\MemoryConfig.ini"
Echo ShowNotice^=0 >> "%APPDATA%\Wise Memory Optimzer\MemoryConfig.ini"
Echo LowMem^=400 >> "%APPDATA%\Wise Memory Optimzer\MemoryConfig.ini"
Echo ^[General^] >> "%APPDATA%\Wise Memory Optimzer\MemoryConfig.ini"
Echo SetupVer^=4.14.116 >> "%APPDATA%\Wise Memory Optimzer\MemoryConfig.ini"
Echo MsgIDs^= >> "%APPDATA%\Wise Memory Optimzer\MemoryConfig.ini"
Start "" "%MYWiseMemo%"
GOTO:EOF
)
SET "ERRORLEVEL="
tasklist /fi "IMAGENAME eq WiseMemoryOptimzer.exe" | find /I "WiseMemoryOptimzer.exe"
IF "%ERRORLEVEL%"=="0" ( taskkill /f /t /im RAMRush.exe
GOTO:EOF )
for /f "tokens=1,2,* " %%i in ('REG QUERY HKEY_CURRENT_USER\Software\FTweak\RAMRush /v programfile ^| find /i "programfile"') do set "regramrush=%%k"
SET "MYRAMRush=%PROGRAMFILES(X86)%\RAMRush\RAMRush.exe"
IF EXIST "%PROGRAMFILES%\RAMRush\RAMRush.exe" (
SET "MYRAMRush=%PROGRAMFILES%\RAMRush\RAMRush.exe")
IF EXIST "%MYRAMRush%" (
:RAMRush2
taskkill /f /t /im RAMRush.exe
reg add "HKCU\Software\FTweak\RAMRush" /v ShowMessageWhenOptimizing /t REG_DWORD /d 0x0 /f
reg add "HKCU\Software\FTweak\RAMRush" /v CPUDataFromSystemPerform /t REG_DWORD /d 0x0 /f
reg add "HKCU\Software\FTweak\RAMRush" /v AutoOptimize /t REG_DWORD /d 0x1 /f
IF EXIST "%MYRAMRush%" ( START "" "%MYRAMRush%" -AutoOptimize
GOTO:EOF
) 
IF EXIST "%regramrush%" ( START "" "%regramrush%" -AutoOptimize
GOTO:EOF
)
GOTO:EOF
)
CD /D "%~dp0"
IF EXIST RAMRush.exe GOTO RAMRush2
IF EXIST "%regramrush%" GOTO RAMRush2
GOTO:EOF

:OPTIMIZAR
CLS
Echo Optimizando Closers para maximo rendimiento...
SET "ERRORLEVEL="
tasklist /fi "IMAGENAME eq xxd-0.xem" | find /I "xxd-0.xem"
IF "%ERRORLEVEL%"=="0" (
CLS
wmic process where name="xcoronahost.xem" CALL setpriority 256
wmic process where name="xxd-0.xem" CALL setpriority 256
CLS
Echo Closers Optimizado Correctamente Cerrando Proceso...
TIMEOUT /T 3 >NUL
GOTO:EOF
)
CLS
Echo Optimizando Closers para maximo rendimiento...
TIMEOUT /T 6 >NUL
GOTO OPTIMIZAR

:ENMEMORIA
	SET "ERRORLEVEL="
	tasklist /fi "IMAGENAME eq Steam.exe" | find /I "Steam.exe"
	IF "%ERRORLEVEL%"=="0" (
	Start steam://run/215830
	GOTO:EOF
	)
	START https://www.closersonline.com/signin/
:EsperarClosers
SET "Z1="
SET "ERRORLEVEL="
tasklist /fi "IMAGENAME eq CLOSERS.EXE" | find /I "CLOSERS.EXE"
IF "%ERRORLEVEL%"=="0" (SET "Z1=1")
CLS
SET "ERRORLEVEL="
tasklist /fi "IMAGENAME eq CW.EXE" | find /I "CW.EXE"
IF "%ERRORLEVEL%"=="1" (
CLS
IF NOT "%Z1%"=="1" Echo Abra Closers desde el Website o desde Steam...
IF "%Z1%"=="1" Echo Pulse el Boton de Play en Closers para continuar...
TIMEOUT /T 6 >NUL
GOTO EsperarClosers
)
GOTO:EOF
exit