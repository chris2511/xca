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
OutFile "xca.exe"

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
  ; Set output path to the installation directory.
  SetOutPath $INSTDIR
  ; Put file there
  File "Release\xca.exe"
  File "img\bigcert.png"
  File "img\bigcsr.png"
  File "img\bigkey.png"
  File "img\bigtemp.png"
  File "img\halfkey.png"
  File "img\invalidcert.png"
  File "img\invalidcertkey.png"
  File "img\key.png"
  File "img\req.png"
  File "img\reqkey.png"
  File "img\template.png"
  File "img\validcert.png"
  File "img\validcertkey.png"
  File "c:\devel\db-4.0.14\build_win32\Release\libdb40.dll"
  File "c:\devel\openssl-0.9.6g\out32dll\Release\SSLeay32.dll"
  File "c:\devel\openssl-0.9.6g\out32dll\Release\libeay32.dll"
  File "e:\win\qt2\bin\msvcrt.dll"
  File "c:\windows\system\msvcp60.dll"
  File "e:\win\qt2\bin\qt-mt230nc.dll"
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
  CreateShortCut "$SMPROGRAMS\xca\xca xca.lnk" "$INSTDIR\xca.exe" "" "$INSTDIR\xca.exe" 0
SectionEnd

; uninstall stuff

UninstallText "This will uninstall xca. Hit next to continue."

; special uninstall section.
Section "Uninstall"
  ; remove registry keys
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\xca"
  DeleteRegKey HKLM SOFTWARE\xca
  ; remove files
  Delete $INSTDIR\xca.exe
  ; MUST REMOVE UNINSTALLER, too
  Delete $INSTDIR\uninstall.exe
  ; remove shortcuts, if any.
  Delete "$SMPROGRAMS\xca\*.*"
  ; remove directories used.
  RMDir "$SMPROGRAMS\xca"
  
  ;RMDir "$INSTDIR" NO, we keep the databasefiles xca.db
  Delete "$INSTDIR\xca\*.png"
  Delete "$INSTDIR\xca\*.dll"
  Delete "$INSTDIR\bigcert.png"
  Delete "$INSTDIR\bigcsr.png"
  Delete "$INSTDIR\bigkey.png"
  Delete "$INSTDIR\bigtemp.png"
  Delete "$INSTDIR\halfkey.png"
  Delete "$INSTDIR\invalidcert.png"
  Delete "$INSTDIR\invalidcertkey.png"
  Delete "$INSTDIR\key.png"
  Delete "$INSTDIR\req.png"
  Delete "$INSTDIR\reqkey.png"
  Delete "$INSTDIR\template.png"
  Delete "$INSTDIR\validcert.png"
  Delete "$INSTDIR\validcertkey.png"
  Delete "$INSTDIR\libdb40.dll"
  Delete "$INSTDIR\SSLeay32.dll"
  Delete "$INSTDIR\libeay32.dll"
  Delete "$INSTDIR\msvcrt.dll"
  Delete "$INSTDIR\msvcp60.dll"
  Delete "$INSTDIR\qt-mt230nc.dll"
SectionEnd

; eof
