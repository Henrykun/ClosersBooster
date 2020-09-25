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
echo  [C] Cerrar Todo Menos Closers
echo  [D] Cerrar Todo Menos Closers y Discord
echo  [S] Cerrar Todo Menos Closers y Steam
echo  [M] Cerrar Todo Menos Closers, Steam y Discord
echo  [G] Cerrar Todo Menos Closers y Google Chrome
echo  [F] Cerrar Todo Menos Closers y Firefox
echo %linea%
Echo  [X] Reactivar servicio de Impresoras
echo %linea%
echo  NOTA: Se te recomienda que guardes todo tu trabajo en Microsoft Office, 
echo  Navegadores, etc.. antes de ejecutar esta Herramienta, para que no 
echo  pierdas el trabajo realizado.
echo %linea%

:Validar
SET /p var= ^> Seleccione una opcion [...]: 
IF /I "%var%"=="A" call :Todos
IF /I "%var%"=="C" call :Closers
IF /I "%var%"=="D" call :Discord
IF /I "%var%"=="S" call :Steam
IF /I "%var%"=="G" call :Google
IF /I "%var%"=="F" call :Firefox
IF /I "%var%"=="X" call :Impresora
IF /I "%var%"=="M" call :SteamDiscord
SET "var="
Goto INICIO

:Todos
CLS
Goto Generico

:Closers
CLS
taskkill /f /t /im Chrome.exe
taskkill /f /t /im Steam.exe
taskkill /f /t /im Discord.exe
taskkill /f /t /im Firefox.exe
Goto Generico

:Discord
CLS
taskkill /f /t /im Chrome.exe
taskkill /f /t /im Steam.exe
taskkill /f /t /im Firefox.exe
Goto Generico

:Steam
CLS
taskkill /f /t /im Chrome.exe
taskkill /f /t /im Discord.exe
taskkill /f /t /im Firefox.exe
Goto Generico

:Google
CLS
taskkill /f /t /im Steam.exe
taskkill /f /t /im Discord.exe
taskkill /f /t /im Firefox.exe
Goto Generico

:Firefox
CLS
taskkill /f /t /im Chrome.exe
taskkill /f /t /im Steam.exe
taskkill /f /t /im Discord.exe
Goto Generico

:SteamDiscord
taskkill /f /t /im Chrome.exe
taskkill /f /t /im Firefox.exe
Goto Generico

:Impresora
CLS
sc start Spooler
Echo Servioio de impresion activado correctamente, pulsa una tecla para salir.
PAUSE > NUL
EXIT

:Generico
for /f "tokens=2 delims=()" %%x in ('sc query state^=all ^| findstr Google ^| findstr Update') do sc stop %%x
for /f "tokens=2 delims=()" %%x in ('sc query state^=all ^| findstr Adobe ^| findstr Update') do sc stop %%x
sc stop AdobeARMservice
sc stop DHCPServer
sc stop Spooler
sc stop VBoxSDS
sc stop cmcore
sc stop gupdate
sc stop gupdatem
sc stop iphlpsvc
sc stop MozillaMaintenance
sc stop teamviewer
sc stop wlidsvc
sc stop wuauserv
taskkill /f /t /im AcroRd32.exe
taskkill /f /t /im CCUpdate.exe
taskkill /f /t /im CCleaner.exe
taskkill /f /t /im CCleaner64.exe
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
taskkill /f /t /im NOTEPAD.exe
taskkill /f /t /im OneDrive.exe
taskkill /f /t /im POWERPNT.exe
taskkill /f /t /im SndVol.exe 
taskkill /f /t /im SystemPropertiesAdvanced.exe
taskkill /f /t /im SystemSettings.exe
taskkill /f /t /im SystemSettingsBroker.exe
taskkill /f /t /im Taskmgr.exe
taskkill /f /t /im TeamViewer.exe
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
taskkill /f /t /im systeminfo.exe
taskkill /f /t /im winword.exe
EXIT