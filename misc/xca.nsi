
; This is the .nsi script for creating the nullsoft windows installer

; The name of the installer
Name "XCA"
Caption "XCA ${VERSION}${EXTRA_VERSION} Setup"
OutFile "setup_xca-${VERSION}${EXTRA_VERSION}.exe"

InstallDir $PROGRAMFILES\xca
; Registry key to check for directory (so if you install again, it will
; overwrite the old one automatically)
InstallDirRegKey HKLM SOFTWARE\xca "Install_Dir"

SetCompressor /SOLID lzma

;-----------------------------------
!include "MUI.nsh"

!define MUI_ABORTWARNING

!define MUI_FINISHPAGE_TEXT $(DESC_Finish)
!define MUI_FINISHPAGE_NOREBOOTSUPPORT
!define MUI_FINISHPAGE_RUN "$INSTDIR\xca.exe"

!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "${TOPDIR}/img\bigcert.bmp"
!define MUI_HEADERIMAGE_RIGHT
!define MUI_ICON "${TOPDIR}/img\key.ico"

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
!insertmacro MUI_LANGUAGE "French"
!insertmacro MUI_LANGUAGE "Croatian"

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
  File "xca_db_stat.exe"
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
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\xca" "DisplayName" "XCA (X Certificate and Key Management)"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\xca" "DisplayIcon" "$INSTDIR\xca.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\xca" "UninstallString" "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\xca" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\xca" "Version" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\xca" "URLUpdateInfo" "http://sourceforge.net/projects/xca/"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\xca" "URLInfoAbout" "http://xca.sf.net"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\xca" "HelpLink" "http://xca.sf.net"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\xca" "Publisher" "Christian Hohnstaedt <christian@hohnstaedt.de>"
  WriteRegDWord HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\xca" "NoModify" '1'
  WriteRegDWord HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\xca" "NoRepair" '1'
  WriteUninstaller "uninstall.exe"
SectionEnd

;----------------------------------------
Section "Start Menu Shortcuts" SecShortcut
  CreateDirectory "$SMPROGRAMS\xca"
  CreateShortCut "$SMPROGRAMS\xca\Uninstall.lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0
  CreateShortCut "$SMPROGRAMS\xca\xca.lnk" "$INSTDIR\xca.exe" "" "$INSTDIR\xca.exe" 0
SectionEnd

;----------------------------------------
Section "Translations" SecTrans

  File /nonfatal "lang\*.qm"
  File /nonfatal "${QTDIR}\translations\qt_de.qm"
  File /nonfatal "${QTDIR}\translations\qt_es.qm"
  File /nonfatal "${QTDIR}\translations\qt_ru.qm"
  File /nonfatal "${QTDIR}\translations\qt_fr.qm"
  File /nonfatal "${QTDIR}\translations\qt_hr.qm"
  File /nonfatal "${QTDIR}\translations\qt_tr.qm"

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
  Delete $INSTDIR\xca_db_stat.exe
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
  LangString DESC_SecMain ${LANG_FRENCH}  "application XCA."
  LangString DESC_SecMain ${LANG_CROATIAN}  "XCA aplikacija."

  LangString DESC_SecShortcut ${LANG_ENGLISH} "Shortcuts on the desktop and the menu."
  LangString DESC_SecShortcut ${LANG_GERMAN}  "Programmgruppe auf dem Desktop und im Menu."
  LangString DESC_SecShortcut ${LANG_FRENCH} "Raccourcis sur le bureau et dans le menu."
  LangString DESC_SecShortcut ${LANG_CROATIAN} "Precac na radnoj površini i izborniku."

  LangString DESC_SecFiles ${LANG_ENGLISH} "File association for *.xdb *.xca *.pem and 'open with' for *.crt *.crl *.pfx *.p7b *.cer"
  LangString DESC_SecFiles ${LANG_GERMAN}  "Registrierung der Dateiendung *.xdb *.xca *.pem und 'Öffnen mit' für *.crt *.crl *.pfx *.p7b *.cer"
  LangString DESC_SecFiles ${LANG_FRENCH} "Application par défault pour *.xdb *.xca *.pem et 'Ouvrir avec' pour *.crt *.crl *.pfx *.p7b *.cer"
  LangString DESC_SecFiles ${LANG_CROATIAN} "Osnovna aplikacija za datoteke *.xdb *.xca *.pem i 'Otvori s' za *.crt *.crl *.pfx *.p7b *.cer"

  LangString DESC_SecTrans ${LANG_ENGLISH} "Translations for german, russian, spanish, french and croatian."
  LangString DESC_SecTrans ${LANG_GERMAN}  "Übersetzungen in deutsch, russisch, spanisch kroatisch und französisch."
  LangString DESC_SecTrans ${LANG_FRENCH} "Traductions pour l'allemand, le russe, l'espagnol, le français et le croate."
  LangString DESC_SecTrans ${LANG_CROATIAN} "Prijevodi na njemacki, ruski, španjolski, francuski i hrvatski jezik."

  ;Assign language strings to sections
  !insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecMain} $(DESC_SecMain)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecShortcut} $(DESC_SecShortcut)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecFiles} $(DESC_SecFiles)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecTrans} $(DESC_SecTrans)
  !insertmacro MUI_FUNCTION_DESCRIPTION_END

LangString DESC_Finish ${LANG_ENGLISH} "\r\nEnjoy XCA and free Software"
LangString DESC_Finish ${LANG_GERMAN} "\r\nViel Spass mit XCA und freier Software"
LangString DESC_Finish ${LANG_FRENCH} "\r\nAmusez-vous bien avec XCA et les logiciels libres"
LangString DESC_Finish ${LANG_CROATIAN} "\r\nUživajte u XCA i slobodnom softveru"

;-----------------------------------

Function .onInit
  !insertMacro MUI_LANGDLL_DISPLAY
FunctionEnd
Function un.onInit
  !insertMacro MUI_UNGETLANGUAGE
FunctionEnd

; eof
