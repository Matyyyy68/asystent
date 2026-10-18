!include nsDialogs.nsh
!include LogicLib.nsh
!include MUI2.nsh
!ifndef BUILD_UNINSTALLER
Var SentinelAutoStart
Var SentinelAutoStartControl
!macro customWelcomePage
  !define MUI_WELCOMEPAGE_TITLE "Witaj w Sentinel AI User"
  !define MUI_WELCOMEPAGE_TEXT "Lokalna analiza podejrzanych wiadomości i domen.$\r$\n$\r$\nTen kreator instaluje interfejs, silnik .NET oraz host Chrome/Edge. Nie zmienia DNS, zapory ani zabezpieczeń Windows.$\r$\n$\r$\nLista CERT Polska jest pobierana dopiero na Twoje żądanie. Rozszerzenie przeglądarki wymaga ręcznego włączenia.$\r$\n$\r$\nWersja rozwojowa: wykrywanie i ostrzeganie, bez gwarantowanej blokady."
  !insertmacro MUI_PAGE_WELCOME
!macroend
!macro customPageAfterChangeDir
  Page custom SentinelPreferences SentinelPreferencesLeave
!macroend
Function SentinelPreferences
  !insertmacro MUI_HEADER_TEXT "Twoja prywatność, Twoja decyzja" "Sentinel AI User — ustawienia instalacji"
  nsDialogs::Create 1018
  Pop $0
  ${NSD_CreateLabel} 0 0 100% 44u "Analiza odbywa się lokalnie. Brak telemetrii i konta Sentinel. Zamknięcie okna chowa aplikację do zasobnika. Obserwację DNS włączysz jawnie w aplikacji."
  Pop $0
  ${NSD_CreateCheckbox} 0 54u 100% 18u "Uruchamiaj Sentinel AI razem z Windows"
  Pop $SentinelAutoStartControl
  ${NSD_Check} $SentinelAutoStartControl
  IfFileExists "$INSTDIR\Sentinel AI.exe" 0 sentinelNewInstall
  ReadRegStr $0 HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "Sentinel AI"
  ${If} $0 == ""
    ${NSD_Uncheck} $SentinelAutoStartControl
  ${EndIf}
sentinelNewInstall:
  ${NSD_CreateLabel} 0 88u 100% 40u "Dane i historia pozostają w profilu użytkownika. Aktualizacja oraz odinstalowanie je zachowują. Historię można usunąć w sekcji Prywatność."
  Pop $0
  nsDialogs::Show
FunctionEnd
Function SentinelPreferencesLeave
  ${NSD_GetState} $SentinelAutoStartControl $SentinelAutoStart
FunctionEnd
!macro customInstall
  ; Electron's Chromium sandbox needs read/execute access to installed app files.
  ; Grant it only to this program folder; keep the user's data directory private.
  ExecWait '"$SYSDIR\icacls.exe" "$INSTDIR" /grant *S-1-15-2-1:(OI)(CI)(RX) /T /C' $0
  ${If} $0 != 0
    MessageBox MB_OK|MB_ICONSTOP "Nie udało się skonfigurować uprawnień piaskownicy Chromium. Instalacja może się nie uruchomić; sprawdź uprawnienia folderu instalacji."
    Abort
  ${EndIf}
  ExecWait '"$INSTDIR\resources\engine\Sentinel.UrlHost.exe" --register' $0
  ${If} $0 != 0
    MessageBox MB_OK|MB_ICONEXCLAMATION "Host przeglądarki nie został zarejestrowany. Wykonaj diagnostykę i naprawę instalacji."
  ${EndIf}
  ${If} $SentinelAutoStart == ${BST_CHECKED}
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "Sentinel AI" "$\"$INSTDIR\Sentinel AI.exe$\" --minimized"
  ${Else}
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "Sentinel AI"
  ${EndIf}
!macroend
!endif
!macro customUnInstall
    ExecWait '"$INSTDIR\resources\engine\Sentinel.UrlHost.exe" --unregister' $0
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "Sentinel AI"

!macroend
