; Build with NSIS 3.11+; all payload paths and version come from package-installer.py.
Unicode true
Target amd64-unicode
RequestExecutionLevel user
SetCompressor /SOLID lzma
SetCompressorDictSize 32
CRCCheck force
ManifestDPIAware true
ManifestSupportedOS all

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "WinVer.nsh"
!include "x64.nsh"

!ifndef PAYLOAD_DIR
 !error "Missing PAYLOAD_DIR"
!endif
!ifndef REMOVE_MANIFEST
 !error "Missing REMOVE_MANIFEST"
!endif

Name "Sentinel AI"
OutFile "${OUTPUT_EXE}"
InstallDir "$LOCALAPPDATA\Programs\Sentinel AI"
InstType "Dla mnie (ochrona na tym komputerze)"
InstType "Dla organizacji (mam kod od administratora)"
BrandingText "Sentinel AI • ${APP_VERSION}"
VIProductVersion "${APP_VERSION}.0"
VIAddVersionKey /LANG=1045 "ProductName" "Sentinel AI"
VIAddVersionKey /LANG=1045 "ProductVersion" "${APP_VERSION}"
VIAddVersionKey /LANG=1045 "FileVersion" "${APP_VERSION}.0"
VIAddVersionKey /LANG=1045 "FileDescription" "Instalator Sentinel AI dla Windows x64"
VIAddVersionKey /LANG=1045 "LegalCopyright" "Sentinel AI"
ShowInstDetails nevershow
ShowUninstDetails nevershow
Var AppMutex
Var SelectedVariant
Var ExistingVariant
Var DeleteUserData

!define MUI_ABORTWARNING
!define MUI_BGCOLOR "F5F7FA"
!define MUI_TEXTCOLOR "172033"
!define MUI_ICON "${NSISDIR}/Contrib/Graphics/Icons/modern-install-blue-full.ico"
!define MUI_UNICON "${NSISDIR}/Contrib/Graphics/Icons/modern-uninstall-blue-full.ico"
!define MUI_WELCOMEPAGE_TITLE "Zainstaluj Sentinel AI"
!define MUI_WELCOMEPAGE_TEXT "Ten kreator zainstaluje Sentinel AI na Twoim koncie Windows.$\r$\n$\r$\nProgram sprawdza podejrzane wiadomości i adresy lokalnie. Podstawowa analiza działa offline. Możesz dodać własne materiały bezpieczeństwa i włączyć opcjonalny lokalny model AI w ustawieniach.$\r$\n$\r$\nZamknij Sentinel AI przed rozpoczęciem. Nie potrzebujesz konta administratora.$\r$\n$\r$\nKliknij Dalej, aby kontynuować."
!insertmacro MUI_PAGE_WELCOME
!define MUI_PAGE_CUSTOMFUNCTION_LEAVE ValidateProductVariant
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_TITLE "Sentinel AI jest gotowy do uruchomienia"
!define MUI_FINISHPAGE_TEXT "Znajdziesz program w menu Start pod nazwą Sentinel AI.$\r$\n$\r$\nPrzy pierwszym uruchomieniu sprawdź lokalną konfigurację komputera. Analiza okien pozostanie wyłączona, dopóki jej samodzielnie nie włączysz."
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchApplication
!define MUI_FINISHPAGE_RUN_TEXT "Uruchom Sentinel AI"
!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\app\Pomoc.html"
!define MUI_FINISHPAGE_SHOWREADME_TEXT "Otwórz krótką instrukcję"
!define MUI_FINISHPAGE_SHOWREADME_NOTCHECKED
!insertmacro MUI_PAGE_FINISH
!define MUI_UNCONFIRMPAGE_TEXT_TOP "Sentinel AI zostanie usunięty z tego konta Windows. W osobnym pytaniu możesz zdecydować, czy usunąć też bazę danych. Domyślnie historia i ustawienia zostają zachowane."
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH
!insertmacro MUI_LANGUAGE "Polish"

; Hold the same named mutex as the desktop application for the entire operation.
; Never terminate the user's process or overwrite DLLs while it is running.
!macro LockApplication Prefix
Function ${Prefix}LockApplication
 retry:
  System::Call 'kernel32::CreateMutexW(p 0, i 0, w "Local\SentinelAI.Desktop") p.r0 ?e'
  Pop $1
  ${If} $0 == 0
   MessageBox MB_OK|MB_ICONSTOP "Nie można przygotować instalacji. Uruchom ponownie komputer i spróbuj jeszcze raz." /SD IDOK
   SetErrorLevel 2
   Abort
  ${EndIf}
  ${If} $1 == 183
   System::Call 'kernel32::CloseHandle(p r0)'
   IfSilent busy 0
   MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "Zamknij Sentinel AI oraz inne okna jego instalatora, a następnie kliknij Ponów próbę." IDRETRY retry
  busy:
   SetErrorLevel 2
   Abort
  ${EndIf}
  StrCpy $AppMutex $0
FunctionEnd
Function ${Prefix}UnlockApplication
 ${If} $AppMutex != 0
  System::Call 'kernel32::CloseHandle(p $AppMutex)'
  StrCpy $AppMutex 0
 ${EndIf}
FunctionEnd
!macroend
!insertmacro LockApplication ""
!insertmacro LockApplication "un."

Function .onInit
 SetShellVarContext current
 SetRegView 64
 ; Deliberately use a private, fixed application location even with /D.
 StrCpy $INSTDIR "$LOCALAPPDATA\Programs\Sentinel AI"
 ReadRegStr $ExistingVariant HKCU "Software\SentinelAI" "ProductVariant"
 ${If} $ExistingVariant == ""
  ReadRegStr $0 HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI" "DisplayName"
  ${If} $0 != ""
   ; Products installed before the variant marker are safely treated as User.
   StrCpy $ExistingVariant "User"
  ${EndIf}
 ${EndIf}
 ${If} $ExistingVariant == "EnterpriseClient"
  SetCurInstType 1
 ${Else}
  SetCurInstType 0
 ${EndIf}
 ${IfNot} ${RunningX64}
  MessageBox MB_OK|MB_ICONSTOP "Sentinel AI wymaga 64-bitowego Windows 10 lub Windows 11." /SD IDOK
  SetErrorLevel 3
  Abort
 ${EndIf}
 ${IfNot} ${AtLeastWin10}
  MessageBox MB_OK|MB_ICONSTOP "Sentinel AI wymaga Windows 10 lub Windows 11." /SD IDOK
  SetErrorLevel 3
  Abort
 ${EndIf}
 Call LockApplication
FunctionEnd

Function .onGUIEnd
 Call UnlockApplication
FunctionEnd
Function .onInstSuccess
 Call UnlockApplication
 ${If} $SelectedVariant == "user"
  WriteRegStr HKCU "Software\SentinelAI" "ProductVariant" "User"
 ${Else}
  WriteRegStr HKCU "Software\SentinelAI" "ProductVariant" "EnterpriseClient"
 ${EndIf}
 ExecWait '"$INSTDIR\app\BrowserHost\Sentinel.UrlHost.exe" --register' $0
 ${If} $0 != 0
  MessageBox MB_OK|MB_ICONEXCLAMATION "Nie udało się zarejestrować lokalnego połączenia z przeglądarką. Sentinel AI działa dalej; szczegóły znajdziesz w Pomocy." /SD IDOK
 ${EndIf}
FunctionEnd
Function LaunchApplication
 Call UnlockApplication
 ExecShell "open" "$INSTDIR\app\Sentinel.Desktop.exe" "--sentinel-variant=$SelectedVariant"
FunctionEnd

Section "Sentinel AI (wymagane)" SEC_APP
 SectionIn RO
 SetOutPath "$INSTDIR\app"
 SetOverwrite on
 ClearErrors
 File /r "${PAYLOAD_DIR}/*"
 IfErrors installFailed
 WriteUninstaller "$INSTDIR\Odinstaluj.exe"
 IfErrors installFailed
 CreateDirectory "$SMPROGRAMS\Sentinel AI"
 CreateShortCut "$SMPROGRAMS\Sentinel AI\Sentinel AI.lnk" "$INSTDIR\app\Sentinel.Desktop.exe"
 CreateShortCut "$SMPROGRAMS\Sentinel AI\Pomoc.lnk" "$INSTDIR\app\Pomoc.html"
 CreateShortCut "$SMPROGRAMS\Sentinel AI\Odinstaluj.lnk" "$INSTDIR\Odinstaluj.exe"
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI" "DisplayName" "Sentinel AI"
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI" "DisplayVersion" "${APP_VERSION}"
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI" "Publisher" "Sentinel AI"
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI" "InstallLocation" "$INSTDIR"
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI" "DisplayIcon" "$INSTDIR\app\Sentinel.Desktop.exe"
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI" "UninstallString" '$\"$INSTDIR\Odinstaluj.exe$\"'
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI" "QuietUninstallString" '$\"$INSTDIR\Odinstaluj.exe$\" /S'
 WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI" "EstimatedSize" ${ESTIMATED_KB}
 WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI" "NoModify" 1
 WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI" "NoRepair" 1
 IfErrors installFailed
 Goto installDone
 installFailed:
  MessageBox MB_OK|MB_ICONSTOP "Nie udało się ukończyć instalacji. Sprawdź wolne miejsce na dysku i spróbuj ponownie. Twoja historia i ustawienia nie zostały usunięte." /SD IDOK
  SetErrorLevel 1
  Abort
 installDone:
SectionEnd

Section "Sentinel AI User" SEC_PROFILE_USER
 SectionIn 1 RO
 StrCpy $SelectedVariant "user"
SectionEnd

Section "Enterprise Client (połączenie z serwerem firmowym)" SEC_PROFILE_ENTERPRISE
 SectionIn 2 RO
 StrCpy $SelectedVariant "enterprise-client"
SectionEnd

Section "Skrót na pulpicie" SEC_DESKTOP
 SectionIn 1 2
 CreateShortCut "$DESKTOP\Sentinel AI.lnk" "$INSTDIR\app\Sentinel.Desktop.exe"
SectionEnd
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
 !insertmacro MUI_DESCRIPTION_TEXT ${SEC_APP} "Program i wszystkie potrzebne składniki. Skróty pojawią się w menu Start."
 !insertmacro MUI_DESCRIPTION_TEXT ${SEC_PROFILE_USER} "Wariant dla osoby prywatnej. Analiza regułowa działa lokalnie i offline."
 !insertmacro MUI_DESCRIPTION_TEXT ${SEC_PROFILE_ENTERPRISE} "Wybierz ten wariant tylko wtedy, gdy administrator przekazał Ci adres serwera i jednorazowy kod zaproszenia."
 !insertmacro MUI_DESCRIPTION_TEXT ${SEC_DESKTOP} "Dodaje ikonę Sentinel AI na Twoim pulpicie."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Function ValidateProductVariant
 SectionGetFlags ${SEC_PROFILE_USER} $0
 IntOp $0 $0 & ${SF_SELECTED}
 ${If} $0 != 0
  StrCpy $SelectedVariant "user"
 ${Else}
  StrCpy $SelectedVariant "enterprise-client"
 ${EndIf}
 ${If} $ExistingVariant != ""
  ${If} $ExistingVariant == "User"
   ${If} $SelectedVariant != "user"
    MessageBox MB_OK|MB_ICONSTOP "Wariant instalacji jest zachowywany podczas aktualizacji. Zmiana User/Enterprise nie jest obsługiwana przez ponowną instalację." /SD IDOK
    Abort
   ${EndIf}
  ${ElseIf} $SelectedVariant != "enterprise-client"
   MessageBox MB_OK|MB_ICONSTOP "Wariant instalacji jest zachowywany podczas aktualizacji. Zmiana User/Enterprise nie jest obsługiwana przez ponowną instalację." /SD IDOK
   Abort
  ${EndIf}
 ${EndIf}
FunctionEnd

Function un.onInit
 SetShellVarContext current
 SetRegView 64
 StrCpy $DeleteUserData "0"
 IfSilent unSkipDataQuestion
 MessageBox MB_YESNO|MB_ICONQUESTION "Czy usunąć lokalną historię Sentinel AI i ustawienia? Inne pliki w wybranym folderze pozostaną nietknięte." /SD IDNO IDYES unRemoveData
 Goto unSkipDataQuestion
 unRemoveData:
  StrCpy $DeleteUserData "1"
 unSkipDataQuestion:
 Call un.LockApplication
FunctionEnd
Function un.onGUIEnd
 Call un.UnlockApplication
FunctionEnd
Function un.onUninstSuccess
 Call un.UnlockApplication
FunctionEnd

Section "Uninstall"
 DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "SentinelAI"
 ExecWait '"$INSTDIR\app\BrowserHost\Sentinel.UrlHost.exe" --unregister' $0
 DeleteRegKey HKCU "Software\Google\Chrome\NativeMessagingHosts\com.sentinelai.urlcheck"
 DeleteRegKey HKCU "Software\Microsoft\Edge\NativeMessagingHosts\com.sentinelai.urlcheck"
 Delete "$INSTDIR\app\BrowserHost\com.sentinelai.urlcheck.json"
 Delete "$INSTDIR\app\BrowserHost\com.sentinelai.urlcheck.json.new"
 ; Only delete files listed when the package was built. Never recursively remove
 ; the application root: a user might have placed private files or data there.
 !include "${REMOVE_MANIFEST}"
 Delete "$DESKTOP\Sentinel AI.lnk"
 Delete "$SMPROGRAMS\Sentinel AI\Sentinel AI.lnk"
 Delete "$SMPROGRAMS\Sentinel AI\Pomoc.lnk"
 Delete "$SMPROGRAMS\Sentinel AI\Odinstaluj.lnk"
 RMDir "$SMPROGRAMS\Sentinel AI"
 DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI"
 ; The server credential is not user history and must not survive uninstall.
 Delete "$LOCALAPPDATA\SentinelAI\enterprise-credential.bin"
 Delete "$LOCALAPPDATA\SentinelAI\enterprise-credential.bin.new"
 ${If} $DeleteUserData == "1"
  ClearErrors
  FileOpen $0 "$LOCALAPPDATA\SentinelAI\data-path.txt" r
  IfErrors unKeepData
  FileRead $0 $1
  FileClose $0
  ${If} $1 != ""
   ; Delete only the known SQLite database and sidecars. Never recurse into the selected directory.
   Delete "$1\sentinel.db"
   Delete "$1\sentinel.db-wal"
   Delete "$1\sentinel.db-shm"
   Delete "$1\knowledge.db"
   Delete "$1\knowledge.db-wal"
   Delete "$1\knowledge.db-shm"
   RMDir "$1"
   Delete "$LOCALAPPDATA\SentinelAI\data-path.txt"
   DeleteRegKey HKCU "Software\SentinelAI"
  ${EndIf}
 ${EndIf}
 unKeepData:
 ; ProductVariant and LocalAppData data are retained for safe reinstalls.
 Delete "$INSTDIR\Odinstaluj.exe"
 RMDir "$INSTDIR"
SectionEnd
