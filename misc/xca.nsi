; xca.nsi
;
; This is the .nsi script for creating the nullsoft windows installer

; The name of the installer
Name "X CA"
Caption "X Certification Authority"

; The licenseagreement
LicenseText "You must accept the following BSD like license to continue."
LicenseData COPYRIGHT

; The file to write
OutFile "xca-VERSION.exe"

; The default installation directory
InstallDir $PROGRAMFILES\xca
; Registry key to check for directory (so if you install again, it will 
; overwrite the old one automatically)
InstallDirRegKey HKLM SOFTWARE\xca "Install_Dir"

; The text to prompt the user to enter a directory
ComponentText "This will install the X Certification Authority (c) 2002 by Christian@Hohnstaedt.de"
; The text to prompt the user to enter a directory
DirText "Choose a directory to install in to:"

; The stuff to install
Section "xca (required)"

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
  File "Release\xca.exe"
  File "misc\dn.txt"
  File "misc\eku.txt"
  File "misc\oids.txt"
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
  File "Release\libdb41.dll"
  File "Release\SSLeay32.dll"
  File "Release\libeay32.dll"
  File "Release\msvcrt.dll"
  File "Release\msvcp60.dll"
  File "Release\qt-mt230nc.dll"
  File "doc\*.html"
  ; Write the installation path into the registry
  WriteRegStr HKLM SOFTWARE\xca "Install_Dir" "$INSTDIR"

  ; Write the uninstall keys for Windows
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\xca" "DisplayName" "X CA (remove only)"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\xca" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteUninstaller "uninstall.exe"
SectionEnd

; optional section
Section "Start Menu Shortcuts"
  CreateDirectory "$SMPROGRAMS\xca"
  CreateShortCut "$SMPROGRAMS\xca\Uninstall.lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0
  CreateShortCut "$SMPROGRAMS\xca\xca.lnk" "$INSTDIR\xca.exe" "" "$INSTDIR\xca.exe" 0
SectionEnd

; uninstall stuff

UninstallText "This will uninstall xca. Hit next to continue."

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

; eof
