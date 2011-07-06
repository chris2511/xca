
; This is the .nsi script for creating the nullsoft windows installer

; The name of the installer
Name "XCA"
Caption "XCA ${VERSION} Setup"
OutFile "setup_xca-${VERSION}.exe"

InstallDir $PROGRAMFILES\xca
; Registry key to check for directory (so if you install again, it will
; overwrite the old one automatically)
InstallDirRegKey HKLM SOFTWARE\xca "Install_Dir"

SetCompressor /SOLID lzma

;-----------------------------------
!include "MUI.nsh"

!define MUI_ABORTWARNING

!define MUI_FINISHPAGE_TEXT $(DESC_donation)
!define MUI_FINISHPAGE_NOREBOOTSUPPORT
!define MUI_FINISHPAGE_RUN "$INSTDIR\xca.exe"

;-----------------------------------
; Pagelist

!insertmacro MUI_PAGE_LICENSE "${TOPDIR}/COPYRIGHT"

!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_RESERVEFILE_LANGDLL

!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "German"

;-----------------------------------
; The stuff to install
Section "xca (required)" SecMain

  ClearErrors
  UserInfo::GetName
  IfErrors Win9x
  UserInfo::GetAccountType
  Pop $0
  StrCmp $0 "Admin" 0 Win9x
	SetShellVarContext all
	Goto done
  Win9x:
	SetShellVarContext current
  done:

  ; Set output path to the installation directory.
  SetOutPath $INSTDIR
  ; Put files there
  File "xca.exe"
  File "${TOPDIR}/misc\dn.txt"
  File "${TOPDIR}/misc\eku.txt"
  File "${TOPDIR}/misc\oids.txt"
  File "${TOPDIR}/misc\aia.txt"
  File "${TOPDIR}/misc\*.xca"
  File "doc\*.html"
  File "${BDIR}\mingwm10.dll"

  File "${QTDIR}\bin\QtGui4.dll"
  File "${QTDIR}\bin\QtCore4.dll"
  File /nonfatal "${QTDIR}\bin\libgcc_s_dw2-1.dll"

  File "${INSTALLDIR}\bin\libltdl-7.dll"
  File "${INSTALLDIR}\bin\libeay32.dll"

  ; delete unneeded engine
  Delete "$INSTDIR\libp11-1.dll"
  Delete "$INSTDIR\engine_pkcs11.dll"

  ; remove old images
  ; Write the installation path into the registry
  WriteRegStr HKLM SOFTWARE\xca "Install_Dir" "$INSTDIR"

  ; Write the uninstall keys for Windows
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\xca" "DisplayName" "XCA (remove only)"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\xca" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteUninstaller "uninstall.exe"
SectionEnd

;----------------------------------------
Section "Start Menu Shortcuts" SecShortcut
  CreateDirectory "$SMPROGRAMS\xca"
  CreateShortCut "$SMPROGRAMS\xca\Uninstall.lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0
  CreateShortCut "$SMPROGRAMS\xca\xca.lnk" "$INSTDIR\xca.exe" "" "$INSTDIR\xca.exe" 0
SectionEnd

;----------------------------------------
Function dump_old_db
  FindFirst $0 $1 $2\*.db
  loop:
    StrCmp $1 "" done
    Exec '"$INSTDIR\db_dump.exe" -f "$2\$1.dump" "$2\$1"'
    MessageBox MB_OK "Dumping $2\$1 to $2\$1.dump"
    FindNext $0 $1
    Goto loop
  done:
FunctionEnd

Section "Update" SecUpdate

  SetOutPath $INSTDIR
  File "${BDIR}\db_dump.exe"
  SetShellVarContext current
  StrCpy $2 "$APPDATA\xca"
  Call dump_old_db
  SetShellVarContext all
  StrCpy $2 "$APPDATA\xca"
  Call dump_old_db
  StrCpy $2 "$INSTDIR"
  Call dump_old_db

SectionEnd

Section "Translations" SecTrans

  File /nonfatal "lang\*.qm"
  File /nonfatal "${QTDIR}\translations\qt_de.qm"
  File /nonfatal "${QTDIR}\translations\qt_es.qm"
  File /nonfatal "${QTDIR}\translations\qt_ru.qm"
  File /nonfatal "${QTDIR}\translations\qt_fr.qm"

SectionEnd

;----------------------------------------
Section "File association" SecFiles
  ReadRegStr $1 HKCR ".xdb" ""
  StrCmp $1 "" NoBackup1
  StrCmp $1 "xca_db" NoBackup1
    WriteRegStr HKCR ".xdb" "backup_val" $1
NoBackup1:
  WriteRegStr HKCR ".xdb" "" "xca_db"
  ReadRegStr $0 HKCR "xca_db" ""
  StrCmp $0 "" 0 Skip1
    WriteRegStr HKCR "xca_db" "" "XCA database"
    WriteRegStr HKCR "xca_db\shell" "" "open"
    WriteRegStr HKCR "xca_db\DefaultIcon" "" "$INSTDIR\xca.exe,1"
    WriteRegStr HKCR "xca_db\shell\open\command" "" '$INSTDIR\xca.exe -d "%1"'
Skip1:

  ReadRegStr $1 HKCR ".xca" ""
  StrCmp $1 "" NoBackup2
  StrCmp $1 "xca_template" NoBackup2
    WriteRegStr HKCR ".xca" "backup_val" $1
NoBackup2:
  WriteRegStr HKCR ".xca" "" "xca_template"
  ReadRegStr $0 HKCR "xca_template" ""
  StrCmp $0 "" 0 Skip2
    WriteRegStr HKCR "xca_template" "" "XCA Template"
    WriteRegStr HKCR "xca_template\shell" "" "open"
    WriteRegStr HKCR "xca_template\DefaultIcon" "" "$INSTDIR\xca.exe,2"
    WriteRegStr HKCR "xca_template\shell\open\command" "" '$INSTDIR\xca.exe -t "%1"'
Skip2:

  ReadRegStr $1 HKCR ".pem" ""
  StrCmp $1 "" NoBackup3
  StrCmp $1 "pem_file" NoBackup3
    WriteRegStr HKCR ".pem" "backup_val" $1
NoBackup3:
  WriteRegStr HKCR ".pem" "" "pem_file"
  ReadRegStr $0 HKCR "pem_file" ""
  StrCmp $0 "" 0 Skip3
    WriteRegStr HKCR "pem_file" "" "Privacy Enhanced Mail"
    WriteRegStr HKCR "pem_file\shell" "" "open"
    WriteRegStr HKCR "pem_file\DefaultIcon" "" "$INSTDIR\xca.exe,0"
    WriteRegStr HKCR "pem_file\shell\open\command" "" '$INSTDIR\xca.exe -P "%1"'
Skip3:

  ReadRegStr $1 HKCR ".crt" ""
  StrCmp $1 "" +3
    WriteRegStr HKCR "$1\shell\open_xca" "" "Open with XCA"
    WriteRegStr HKCR "$1\shell\open_xca\command" "" '$INSTDIR\xca.exe -c "%1"'
  ReadRegStr $1 HKCR ".crl" ""
  StrCmp $1 "" +3
    WriteRegStr HKCR "$1\shell\open_xca" "" "Open with XCA"
    WriteRegStr HKCR "$1\shell\open_xca\command" "" '$INSTDIR\xca.exe -l "%1"'
  ReadRegStr $1 HKCR ".pfx" ""
  StrCmp $1 "" +3
    WriteRegStr HKCR "$1\shell\open_xca" "" "Open with XCA"
    WriteRegStr HKCR "$1\shell\open_xca\command" "" '$INSTDIR\xca.exe -p "%1"'
  ReadRegStr $1 HKCR ".p7b" ""
  StrCmp $1 "" +3
    WriteRegStr HKCR "$1\shell\open_xca" "" "Open with XCA"
    WriteRegStr HKCR "$1\shell\open_xca\command" "" '$INSTDIR\xca.exe -7 "%1"'

  System::Call 'Shell32::SHChangeNotify(i 0x8000000, i 0, i 0, i 0)'
SectionEnd

; uninstall stuff
;----------------------------------------
Section "Uninstall"
  ; remove registry keys
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\xca"
  DeleteRegKey HKLM "SOFTWARE\xca"
  DeleteRegKey HKCU "SOFTWARE\xca"
  ; remove files
  Delete $INSTDIR\xca.exe
  Delete $INSTDIR\db_dump.exe
  Delete $INSTDIR\key.ico
  Delete $INSTDIR\key.xpm
  Delete $INSTDIR\*.dll
  Delete $INSTDIR\*.xca
  Delete $INSTDIR\*.txt
  Delete $INSTDIR\*.qm
  Delete $INSTDIR\*.html
  Delete $INSTDIR\*.png
  ; MUST REMOVE UNINSTALLER, too
  Delete $INSTDIR\uninstall.exe
  RMDir $INSTDIR

  ClearErrors
  UserInfo::GetName
  IfErrors Win9x
  UserInfo::GetAccountType
  Pop $0
  StrCmp $0 "Admin" 0 Win9x
	SetShellVarContext all
	Goto done
  Win9x:
	SetShellVarContext current
  done:

;--------------------------------------
  ReadRegStr $1 HKCR ".xdb" ""
  StrCmp $1 "xca_db" 0 Skip
    ReadRegStr $1 HKCR ".xdb" "backup_val"
    StrCmp $1 "" 0 Restore
      DeleteRegKey HKCR ".xdb"
      Goto Skip
Restore:
    WriteRegStr HKCR ".xdb" "" $1
Skip:
  DeleteRegValue HKCR ".xdb" "backup_val"
  DeleteRegKey HKCR "xca_db"

;--------------------------------------
  ReadRegStr $1 HKCR ".xca" ""
  StrCmp $1 "xca_template" 0 Skip1
    ReadRegStr $1 HKCR ".xca" "backup_val"
    StrCmp $1 "" 0 Restore1
      DeleteRegKey HKCR ".xca"
      Goto Skip1
Restore1:
    WriteRegStr HKCR ".xca" "" $1
Skip1:
  DeleteRegValue HKCR ".xca" "backup_val"
  DeleteRegKey HKCR "xca_template"
;--------------------------------------
  ReadRegStr $1 HKCR ".pem" ""
  StrCmp $1 "pem_file" 0 Skip2
    ReadRegStr $1 HKCR ".pem" "backup_val"
    StrCmp $1 "" 0 Restore2
      DeleteRegKey HKCR ".pem"
      Goto Skip2
Restore2:
    WriteRegStr HKCR ".pem" "" $1
Skip2:
  DeleteRegValue HKCR ".pem" "backup_val"
  DeleteRegKey HKCR "pem_file"
;--------------------------------------
  ReadRegStr $1 HKCR ".crt" ""
  StrCmp $1 "" +2
    DeleteRegKey HKCR "$1\shell\open_xca"
  ReadRegStr $1 HKCR ".crl" ""
  StrCmp $1 "" +2
    DeleteRegKey HKCR "$1\shell\open_xca"
  ReadRegStr $1 HKCR ".pfx" ""
  StrCmp $1 "" +2
    DeleteRegKey HKCR "$1\shell\open_xca"
  ReadRegStr $1 HKCR ".p7b" ""
  StrCmp $1 "" +2
    DeleteRegKey HKCR "$1\shell\open_xca"

  System::Call 'Shell32::SHChangeNotify(i 0x8000000, i 0, i 0, i 0)'

  ; remove shortcuts, if any.
  Delete "$SMPROGRAMS\xca\*.*"
  ; remove directories used.
  RMDir "$SMPROGRAMS\xca"
SectionEnd

;-----------------------------------
;Descriptions

  ;Language strings
  LangString DESC_SecMain ${LANG_ENGLISH} "XCA main application."
  LangString DESC_SecMain ${LANG_GERMAN}  "XCA Applikation."

  LangString DESC_SecShortcut ${LANG_ENGLISH} "Shortcuts on the desktop and the menu."
  LangString DESC_SecShortcut ${LANG_GERMAN}  "Programmgruppe auf dem Desktop und im Menu."

  LangString DESC_SecUpdate ${LANG_ENGLISH} "Dumps an old database <= 0.5.1 into an ASCII format, that can be imported by the current Version of XCA."
  LangString DESC_SecUpdate ${LANG_GERMAN}  "Exportiert eine alte Datenbank <= 0.5.1 in ein ASCII format, das mit dieser Version von XCA importiert werden kann."

  LangString DESC_SecFiles ${LANG_ENGLISH} "File association for *.xdb *.xca *.pem and 'open with' for *.crt *.crl *.pfx *.p7b *.cer"
  LangString DESC_SecFiles ${LANG_GERMAN}  "Registrierung der Dateiendung *.xdb *.xca *.pem und 'open with' für *.crt *.crl *.pfx *.p7b *.cer"

  LangString DESC_SecTrans ${LANG_ENGLISH} "Translations for german, russian, spanish, french and russian."
  LangString DESC_SecTrans ${LANG_GERMAN}  "Übersetzungen in deutsch, russisch, spanisch und französisch."

  ;Assign language strings to sections
  !insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecMain} $(DESC_SecMain)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecShortcut} $(DESC_SecShortcut)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecUpdate} $(DESC_SecUpdate)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecFiles} $(DESC_SecFiles)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecTrans} $(DESC_SecTrans)
  !insertmacro MUI_FUNCTION_DESCRIPTION_END

LangString DESC_Donation ${LANG_ENGLISH} \
"Please consider donating for XCA.\r\n\r\n\
If this application saves you time and money, consider returning \
a small share back to me."

LangString DESC_Donation ${LANG_GERMAN} \
"Bitte ziehen Sie eine Spende in Betracht.\r\n\r\n\
Wenn Ihnen dieses Programm Zeit und Geld spart, \
ziehen Sie bitte die Möglichkeit in Betracht mir einen kleinen \
Teil davon abzugeben."

;-----------------------------------
 
Function .onInit
  !insertMacro MUI_LANGDLL_DISPLAY
FunctionEnd
Function un.onInit
  !insertMacro MUI_UNGETLANGUAGE
FunctionEnd

; eof
