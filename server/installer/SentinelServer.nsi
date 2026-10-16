Unicode true
!include "MUI2.nsh"
!ifndef APP_VERSION
!error "APP_VERSION is required"
!endif
!ifndef SERVER_PACKAGE
!error "SERVER_PACKAGE is required"
!endif
!ifndef OUTPUT_EXE
!error "OUTPUT_EXE is required"
!endif
!ifndef SERVER_SCRIPT_DIR
!error "SERVER_SCRIPT_DIR is required"
!endif

Name "Sentinel AI Server ${APP_VERSION}"
OutFile "${OUTPUT_EXE}"
InstallDir "$PROGRAMFILES64\SentinelAI\Server"
InstallDirRegKey HKLM "Software\SentinelAI\Server" "InstallDirectory"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
SetDatablockOptimize on
ShowInstDetails show
ShowUninstDetails show

!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "Sentinel AI Server ${APP_VERSION}"
!define MUI_WELCOMEPAGE_TEXT "Zainstaluj centralny serwer Sentinel AI jako usługę Windows. Domyślnie panel będzie dostępny wyłącznie na tym komputerze. Konfigurację dostępu sieciowego i certyfikatu TLS wykonaj osobno zgodnie z dokumentacją."
!define MUI_FINISHPAGE_TITLE "Instalator Sentinel AI Server"
!define MUI_FINISHPAGE_TEXT "Instalator sprawdził usługę i gotowość API. Dane pozostają w ProgramData po odinstalowaniu."
!define MUI_FINISHPAGE_RUN "$INSTDIR\open-admin-panel.cmd"
!define MUI_FINISHPAGE_RUN_TEXT "Otwórz panel administracyjny"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "Polish"

Section "Sentinel AI Server" SEC_SERVER
  SectionIn RO
  SetOutPath "$INSTDIR"
  File /oname=SentinelServer.zip "${SERVER_PACKAGE}"
  DetailPrint "Rozpakowywanie samodzielnego serwera Windows x64…"
  File "${SERVER_SCRIPT_DIR}\expand-package.ps1"
  ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\expand-package.ps1" -ArchivePath "$INSTDIR\SentinelServer.zip" -DestinationPath "$INSTDIR"' $0
  ${If} $0 != 0
    Abort "Nie udało się rozpakować plików serwera (kod $0)."
  ${EndIf}
  Delete "$INSTDIR\SentinelServer.zip"
  Delete "$INSTDIR\expand-package.ps1"
  FileOpen $0 "$INSTDIR\open-admin-panel.cmd" w
  FileWrite $0 'start "" "http://127.0.0.1:5080/admin/"'
  FileClose $0
  DetailPrint "Tworzenie usługi i pierwszego konta administratora…"
  ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\install-windows-service.ps1" -ProgramDirectory "$INSTDIR"' $0
  ${If} $0 != 0
    Abort "Instalacja usługi lub bootstrap administratora nie powiodły się (kod $0). Dane zachowano."
  ${EndIf}
  WriteRegStr HKLM "Software\SentinelAI\Server" "InstallDirectory" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI.Server" "DisplayName" "Sentinel AI Server"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI.Server" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI.Server" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateDirectory "$SMPROGRAMS\Sentinel AI Server"
  CreateShortCut "$SMPROGRAMS\Sentinel AI Server\Panel administracyjny.lnk" "$INSTDIR\open-admin-panel.cmd"
  CreateShortCut "$SMPROGRAMS\Sentinel AI Server\Odinstaluj Sentinel AI Server.lnk" "$INSTDIR\Uninstall.exe"
SectionEnd

Section "Uninstall"
  ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\remove-windows-service.ps1"' $0
  ${If} $0 != 0
    Abort "Nie udało się zatrzymać/usunąć usługi (kod $0). Pliki i dane pozostawiono."
  ${EndIf}
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI.Server"
  DeleteRegKey HKLM "Software\SentinelAI\Server"
  Delete "$SMPROGRAMS\Sentinel AI Server\Panel administracyjny.lnk"
  Delete "$SMPROGRAMS\Sentinel AI Server\Odinstaluj Sentinel AI Server.lnk"
  RMDir "$SMPROGRAMS\Sentinel AI Server"
  RMDir /r "$INSTDIR"
SectionEnd
