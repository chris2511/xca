; xca.nsi
;
; This is the .nsi script for creating the nullsoft windows installer

; The name of the installer
Name "XCA"
Caption "XCA ${VERSION} Setup"
OutFile "setup.exe"

InstallDir $PROGRAMFILES\xca
; Registry key to check for directory (so if you install again, it will
; overwrite the old one automatically)
InstallDirRegKey HKLM SOFTWARE\xca "Install_Dir"

;SetCompressor /SOLID lzma

;-----------------------------------
!include "MUI.nsh"

!define MUI_ABORTWARNING

!define MUI_FINISHPAGE_TEXT $(DESC_donation)
!define MUI_FINISHPAGE_NOREBOOTSUPPORT
!define MUI_FINISHPAGE_RUN xca.exe

;-----------------------------------
; Pagelist

!insertmacro MUI_PAGE_LICENSE "COPYRIGHT"
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
  StrCmp $0 "Admin" 0 +3
	SetShellVarContext all
	Goto done
	SetShellVarContext current
  Win9x:
	SetShellVarContext current
  done:

  ; Set output path to the installation directory.
  SetOutPath $INSTDIR
  ; Put file there
  File "xca.exe"
  File "misc\dn.txt"
  File "misc\eku.txt"
  File "misc\oids.txt"
  File "misc\aia.txt"
  File "lang\*.qm"
  File "img\bigcert.png"
  File "img\bigcrl.png"
  File "img\bigcsr.png"
  File "img\bigkey.png"
  File "img\bigtemp.png"
  File "img\halfkey.png"
  File "img\invalidcert.png"
  File "img\invalidcertkey.png"
  File "img\key.png"
  File "img\key.ico"
  File "img\key.xpm"
  File "img\netscape.png"
  File "img\req.png"
  File "img\reqkey.png"
  File "img\revoked.png"
  File "img\template.png"
  File "img\validcert.png"
  File "img\validcertkey.png"
  File "img\crl.png"
  File "doc\*.html"

  File "${OPENSSL}\libeay32.dll"
  File "${QTDIR}\QtGui4.dll"
  File "${QTDIR}\QtCore4.dll"
  ; Write the installation path into the registry
  WriteRegStr HKLM SOFTWARE\xca "Install_Dir" "$INSTDIR"

  ; Write the uninstall keys for Windows
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\xca" "DisplayName" "X CA (remove only)"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\xca" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteUninstaller "uninstall.exe"
SectionEnd

; optional section
Section "Start Menu Shortcuts" SecShortcut
  CreateDirectory "$SMPROGRAMS\xca"
  CreateShortCut "$SMPROGRAMS\xca\Uninstall.lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0
  CreateShortCut "$SMPROGRAMS\xca\xca.lnk" "$INSTDIR\xca.exe" "" "$INSTDIR\xca.exe" 0
SectionEnd

; uninstall stuff

;UninstallText "This will uninstall XCA ${VERSION}. Hit next to continue."

; special uninstall section.
Section "Uninstall"
  ; remove registry keys
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\xca"
  DeleteRegKey HKLM "SOFTWARE\xca"
  DeleteRegKey HKCU "SOFTWARE\xca"
  ; remove files
  Delete $INSTDIR\xca.exe
  Delete $INSTDIR\*.png
  Delete $INSTDIR\*.dll
  Delete $INSTDIR\*.ico
  Delete $INSTDIR\*.xpm
  Delete $INSTDIR\*.log
  Delete $INSTDIR\*.txt
  Delete $INSTDIR\*.qm
  Delete $INSTDIR\*.html
  ; MUST REMOVE UNINSTALLER, too
  Delete $INSTDIR\uninstall.exe
  RMDir $INSTDIR

  ClearErrors
  UserInfo::GetName
  IfErrors Win9x
  UserInfo::GetAccountType
  Pop $0
  StrCmp $0 "Admin" 0 +3
	SetShellVarContext all
	Goto done
	SetShellVarContext current
  Win9x:
	SetShellVarContext current
  done:


  ; remove shortcuts, if any.
  Delete "$SMPROGRAMS\xca\*.*"
  ; remove directories used.
  RMDir "$SMPROGRAMS\xca"
SectionEnd

;-----------------------------------
;Descriptions

  ;Language strings
  LangString DESC_SecMain ${LANG_ENGLISH} "XCA main application."
  LangString DESC_SecMain ${LANG_GERMAN} "XCA Applikation."
  LangString DESC_SecShortcut ${LANG_ENGLISH} \
	  "Shortcuts on the desktop and the menu."
  LangString DESC_SecShortcut ${LANG_GERMAN} \
	  "Programmgruppe auf dem Desktop und im Menu."

  ;Assign language strings to sections
  !insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecMain} $(DESC_SecMain)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecShortcut} $(DESC_SecShortcut)
  !insertmacro MUI_FUNCTION_DESCRIPTION_END

LangString DESC_Donation ${LANG_ENGLISH} \
"Please consider donating for XCA.\r\n\r\n\
If this application saves you time and money, consider returning \
a small share back to me.\r\n\r\n \
Please use the PayPal account christian@hohnstaedt.de"

LangString DESC_Donation ${LANG_GERMAN} \
"Bitte ziehen sie eine Spende in Betracht.\r\n\r\n\
Wenn Ihnen dieses Programm Zeit und Geld spart, \
ziehen Sie bitte die Möglichkeit in Betracht mir einen kleinen \
Teil davon abzugeben. \
\r\n\r\nBitte verwenden Sie dafür das PayPal Konto christian@hohnstaedt.de"

;-----------------------------------
 
Function .onInit
  !insertMacro MUI_LANGDLL_DISPLAY
FunctionEnd
Function un.onInit
  !insertMacro MUI_UNGETLANGUAGE
FunctionEnd

; eof
