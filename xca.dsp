# Microsoft Developer Studio Project File - Name="xca" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** NICHT BEARBEITEN **

# TARGTYPE "Win32 (x86) Application" 0x0101

CFG=xca - Win32 Release
!MESSAGE Dies ist kein gültiges Makefile. Zum Erstellen dieses Projekts mit NMAKE
!MESSAGE verwenden Sie den Befehl "Makefile exportieren" und führen Sie den Befehl
!MESSAGE 
!MESSAGE NMAKE /f "xca.mak".
!MESSAGE 
!MESSAGE Sie können beim Ausführen von NMAKE eine Konfiguration angeben
!MESSAGE durch Definieren des Makros CFG in der Befehlszeile. Zum Beispiel:
!MESSAGE 
!MESSAGE NMAKE /f "xca.mak" CFG="xca - Win32 Release"
!MESSAGE 
!MESSAGE Für die Konfiguration stehen zur Auswahl:
!MESSAGE 
!MESSAGE "xca - Win32 Release" (basierend auf  "Win32 (x86) Application")
!MESSAGE "xca - Win32 Debug" (basierend auf  "Win32 (x86) Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "xca - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir ""
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir ""
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD CPP /nologo /W3 /O1 /I "$(QTDIR)\include" /I "$(QTDIR)\mkspecs\win32-msvc" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "UNICODE" /D "QT_DLL" /D "QT_THREAD_SUPPORT" /D "QT_NO_DEBUG" /FD -Zm200 /c
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x407
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 /machine:IX86
# ADD LINK32 $(QTDIR)\lib\qt-mt230nc.lib $(QTDIR)\lib\qtmain.lib kernel32.lib user32.lib gdi32.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib imm32.lib winmm.lib wsock32.lib winspool.lib delayimp.lib SSLeay32.lib libeay32.lib libdb40.lib /nologo /subsystem:windows /machine:IX86 /DELAYLOAD:comdlg32.dll /DELAYLOAD:oleaut32.dll /DELAYLOAD:winmm.dll /DELAYLOAD:wsock32.dll /DELAYLOAD:winspool.dll

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD CPP /nologo /W3 /Gm /Zi /Od /I "$(QTDIR)\include" /I "$(QTDIR)\mkspecs\win32-msvc" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "UNICODE" /D "QT_DLL" /D "QT_THREAD_SUPPORT" /FD /GZ -Zm200 /c
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x407
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 /machine:IX86
# ADD LINK32 $(QTDIR)\lib\qt-mt230nc.lib $(QTDIR)\lib\qtmain.lib kernel32.lib user32.lib gdi32.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib imm32.lib winmm.lib wsock32.lib winspool.lib SSLeay32.lib libeay32.lib libdb40d.lib /nologo /subsystem:windows /incremental:no /debug /machine:IX86 /pdbtype:sept

!ENDIF 

# Begin Target

# Name "xca - Win32 Release"
# Name "xca - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=lib\db_base.cpp
# End Source File
# Begin Source File

SOURCE=lib\db_key.cpp
# End Source File
# Begin Source File

SOURCE=lib\db_temp.cpp
# End Source File
# Begin Source File

SOURCE=lib\db_x509.cpp
# End Source File
# Begin Source File

SOURCE=lib\db_x509req.cpp
# End Source File
# Begin Source File

SOURCE=ExportKey.cpp
# End Source File
# Begin Source File

SOURCE=main.cpp
# End Source File
# Begin Source File

SOURCE=MainWindow.cpp
# End Source File
# Begin Source File

SOURCE=MainWindowKeys.cpp
# End Source File
# Begin Source File

SOURCE=MainWindowTemps.cpp
# End Source File
# Begin Source File

SOURCE=MainWindowX509.cpp
# End Source File
# Begin Source File

SOURCE=MainWindowX509Req.cpp
# End Source File
# Begin Source File

SOURCE=NewX509.cpp
# End Source File
# Begin Source File

SOURCE=lib\pki_base.cpp
# End Source File
# Begin Source File

SOURCE=lib\pki_key.cpp
# End Source File
# Begin Source File

SOURCE=lib\pki_pkcs12.cpp
# End Source File
# Begin Source File

SOURCE=lib\pki_temp.cpp
# End Source File
# Begin Source File

SOURCE=lib\pki_x509.cpp
# End Source File
# Begin Source File

SOURCE=lib\pki_x509req.cpp
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=lib\db_base.h
# End Source File
# Begin Source File

SOURCE=lib\db_key.h

!IF  "$(CFG)" == "xca - Win32 Release"

USERDEP__DB_KE="$(QTDIR)\bin\moc.exe"	
# Begin Custom Build - Moc'ing lib\db_key.h...
InputPath=lib\db_key.h

"lib\moc_db_key.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	$(QTDIR)\bin\moc lib\db_key.h -o lib\moc_db_key.cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

USERDEP__DB_KE="$(QTDIR)\bin\moc.exe"	
# Begin Custom Build - Moc'ing lib\db_key.h...
InputPath=lib\db_key.h

"lib\moc_db_key.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	$(QTDIR)\bin\moc lib\db_key.h -o lib\moc_db_key.cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=lib\db_temp.h

!IF  "$(CFG)" == "xca - Win32 Release"

USERDEP__DB_TE="$(QTDIR)\bin\moc.exe"	
# Begin Custom Build - Moc'ing lib\db_temp.h...
InputPath=lib\db_temp.h

"lib\moc_db_temp.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	$(QTDIR)\bin\moc lib\db_temp.h -o lib\moc_db_temp.cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

USERDEP__DB_TE="$(QTDIR)\bin\moc.exe"	
# Begin Custom Build - Moc'ing lib\db_temp.h...
InputPath=lib\db_temp.h

"lib\moc_db_temp.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	$(QTDIR)\bin\moc lib\db_temp.h -o lib\moc_db_temp.cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=lib\db_x509.h

!IF  "$(CFG)" == "xca - Win32 Release"

USERDEP__DB_X5="$(QTDIR)\bin\moc.exe"	
# Begin Custom Build - Moc'ing lib\db_x509.h...
InputPath=lib\db_x509.h

"lib\moc_db_x509.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	$(QTDIR)\bin\moc lib\db_x509.h -o lib\moc_db_x509.cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

USERDEP__DB_X5="$(QTDIR)\bin\moc.exe"	
# Begin Custom Build - Moc'ing lib\db_x509.h...
InputPath=lib\db_x509.h

"lib\moc_db_x509.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	$(QTDIR)\bin\moc lib\db_x509.h -o lib\moc_db_x509.cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=lib\db_x509req.h

!IF  "$(CFG)" == "xca - Win32 Release"

USERDEP__DB_X50="$(QTDIR)\bin\moc.exe"	
# Begin Custom Build - Moc'ing lib\db_x509req.h...
InputPath=lib\db_x509req.h

"lib\moc_db_x509req.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	$(QTDIR)\bin\moc lib\db_x509req.h -o lib\moc_db_x509req.cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

USERDEP__DB_X50="$(QTDIR)\bin\moc.exe"	
# Begin Custom Build - Moc'ing lib\db_x509req.h...
InputPath=lib\db_x509req.h

"lib\moc_db_x509req.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	$(QTDIR)\bin\moc lib\db_x509req.h -o lib\moc_db_x509req.cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=ExportKey.h

!IF  "$(CFG)" == "xca - Win32 Release"

USERDEP__EXPOR="$(QTDIR)\bin\moc.exe"	
# Begin Custom Build - Moc'ing ExportKey.h...
InputPath=ExportKey.h

"moc_ExportKey.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	$(QTDIR)\bin\moc ExportKey.h -o moc_ExportKey.cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

USERDEP__EXPOR="$(QTDIR)\bin\moc.exe"	
# Begin Custom Build - Moc'ing ExportKey.h...
InputPath=ExportKey.h

"moc_ExportKey.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	$(QTDIR)\bin\moc ExportKey.h -o moc_ExportKey.cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=MainWindow.h

!IF  "$(CFG)" == "xca - Win32 Release"

USERDEP__MAINW="$(QTDIR)\bin\moc.exe"	
# Begin Custom Build - Moc'ing MainWindow.h...
InputPath=MainWindow.h

"moc_MainWindow.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	$(QTDIR)\bin\moc MainWindow.h -o moc_MainWindow.cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

USERDEP__MAINW="$(QTDIR)\bin\moc.exe"	
# Begin Custom Build - Moc'ing MainWindow.h...
InputPath=MainWindow.h

"moc_MainWindow.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	$(QTDIR)\bin\moc MainWindow.h -o moc_MainWindow.cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=NewX509.h

!IF  "$(CFG)" == "xca - Win32 Release"

USERDEP__NEWX5="$(QTDIR)\bin\moc.exe"	
# Begin Custom Build - Moc'ing NewX509.h...
InputPath=NewX509.h

"moc_NewX509.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	$(QTDIR)\bin\moc NewX509.h -o moc_NewX509.cpp

# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

USERDEP__NEWX5="$(QTDIR)\bin\moc.exe"	
# Begin Custom Build - Moc'ing NewX509.h...
InputPath=NewX509.h

"moc_NewX509.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	$(QTDIR)\bin\moc NewX509.h -o moc_NewX509.cpp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=lib\pki_base.h
# End Source File
# Begin Source File

SOURCE=lib\pki_key.h
# End Source File
# Begin Source File

SOURCE=lib\pki_pkcs12.h
# End Source File
# Begin Source File

SOURCE=lib\pki_temp.h
# End Source File
# Begin Source File

SOURCE=lib\pki_x509.h
# End Source File
# Begin Source File

SOURCE=lib\pki_x509req.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# Begin Group "Forms"

# PROP Default_Filter "ui"
# Begin Source File

SOURCE=CertDetail.ui

!IF  "$(CFG)" == "xca - Win32 Release"

USERDEP__CERTD="$(QTDIR)\bin\moc.exe"	"$(QTDIR)\bin\uic.exe"	
# Begin Custom Build - Uic'ing CertDetail.ui...
InputPath=CertDetail.ui

BuildCmds= \
	$(QTDIR)\bin\uic CertDetail.ui -o CertDetail.h \
	$(QTDIR)\bin\uic CertDetail.ui -i CertDetail.h -o CertDetail.cpp \
	$(QTDIR)\bin\moc CertDetail.h -o moc_CertDetail.cpp \
	

"CertDetail.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"CertDetail.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"moc_CertDetail.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

USERDEP__CERTD="$(QTDIR)\bin\moc.exe"	"$(QTDIR)\bin\uic.exe"	
# Begin Custom Build - Uic'ing CertDetail.ui...
InputPath=CertDetail.ui

BuildCmds= \
	$(QTDIR)\bin\uic CertDetail.ui -o CertDetail.h \
	$(QTDIR)\bin\uic CertDetail.ui -i CertDetail.h -o CertDetail.cpp \
	$(QTDIR)\bin\moc CertDetail.h -o moc_CertDetail.cpp \
	

"CertDetail.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"CertDetail.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"moc_CertDetail.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=ExportKey_UI.ui

!IF  "$(CFG)" == "xca - Win32 Release"

USERDEP__EXPORT="$(QTDIR)\bin\moc.exe"	"$(QTDIR)\bin\uic.exe"	
# Begin Custom Build - Uic'ing ExportKey_UI.ui...
InputPath=ExportKey_UI.ui

BuildCmds= \
	$(QTDIR)\bin\uic ExportKey_UI.ui -o ExportKey_UI.h \
	$(QTDIR)\bin\uic ExportKey_UI.ui -i ExportKey_UI.h -o ExportKey_UI.cpp \
	$(QTDIR)\bin\moc ExportKey_UI.h -o moc_ExportKey_UI.cpp \
	

"ExportKey_UI.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"ExportKey_UI.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"moc_ExportKey_UI.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

USERDEP__EXPORT="$(QTDIR)\bin\moc.exe"	"$(QTDIR)\bin\uic.exe"	
# Begin Custom Build - Uic'ing ExportKey_UI.ui...
InputPath=ExportKey_UI.ui

BuildCmds= \
	$(QTDIR)\bin\uic ExportKey_UI.ui -o ExportKey_UI.h \
	$(QTDIR)\bin\uic ExportKey_UI.ui -i ExportKey_UI.h -o ExportKey_UI.cpp \
	$(QTDIR)\bin\moc ExportKey_UI.h -o moc_ExportKey_UI.cpp \
	

"ExportKey_UI.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"ExportKey_UI.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"moc_ExportKey_UI.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=KeyDetail.ui

!IF  "$(CFG)" == "xca - Win32 Release"

USERDEP__KEYDE="$(QTDIR)\bin\moc.exe"	"$(QTDIR)\bin\uic.exe"	
# Begin Custom Build - Uic'ing KeyDetail.ui...
InputPath=KeyDetail.ui

BuildCmds= \
	$(QTDIR)\bin\uic KeyDetail.ui -o KeyDetail.h \
	$(QTDIR)\bin\uic KeyDetail.ui -i KeyDetail.h -o KeyDetail.cpp \
	$(QTDIR)\bin\moc KeyDetail.h -o moc_KeyDetail.cpp \
	

"KeyDetail.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"KeyDetail.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"moc_KeyDetail.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

USERDEP__KEYDE="$(QTDIR)\bin\moc.exe"	"$(QTDIR)\bin\uic.exe"	
# Begin Custom Build - Uic'ing KeyDetail.ui...
InputPath=KeyDetail.ui

BuildCmds= \
	$(QTDIR)\bin\uic KeyDetail.ui -o KeyDetail.h \
	$(QTDIR)\bin\uic KeyDetail.ui -i KeyDetail.h -o KeyDetail.cpp \
	$(QTDIR)\bin\moc KeyDetail.h -o moc_KeyDetail.cpp \
	

"KeyDetail.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"KeyDetail.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"moc_KeyDetail.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=MainWindow_UI.ui

!IF  "$(CFG)" == "xca - Win32 Release"

USERDEP__MAINWI="$(QTDIR)\bin\moc.exe"	"$(QTDIR)\bin\uic.exe"	
# Begin Custom Build - Uic'ing MainWindow_UI.ui...
InputPath=MainWindow_UI.ui

BuildCmds= \
	$(QTDIR)\bin\uic MainWindow_UI.ui -o MainWindow_UI.h \
	$(QTDIR)\bin\uic MainWindow_UI.ui -i MainWindow_UI.h -o MainWindow_UI.cpp \
	$(QTDIR)\bin\moc MainWindow_UI.h -o moc_MainWindow_UI.cpp \
	

"MainWindow_UI.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"MainWindow_UI.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"moc_MainWindow_UI.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

USERDEP__MAINWI="$(QTDIR)\bin\moc.exe"	"$(QTDIR)\bin\uic.exe"	
# Begin Custom Build - Uic'ing MainWindow_UI.ui...
InputPath=MainWindow_UI.ui

BuildCmds= \
	$(QTDIR)\bin\uic MainWindow_UI.ui -o MainWindow_UI.h \
	$(QTDIR)\bin\uic MainWindow_UI.ui -i MainWindow_UI.h -o MainWindow_UI.cpp \
	$(QTDIR)\bin\moc MainWindow_UI.h -o moc_MainWindow_UI.cpp \
	

"MainWindow_UI.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"MainWindow_UI.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"moc_MainWindow_UI.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=NewKey.ui

!IF  "$(CFG)" == "xca - Win32 Release"

USERDEP__NEWKE="$(QTDIR)\bin\moc.exe"	"$(QTDIR)\bin\uic.exe"	
# Begin Custom Build - Uic'ing NewKey.ui...
InputPath=NewKey.ui

BuildCmds= \
	$(QTDIR)\bin\uic NewKey.ui -o NewKey.h \
	$(QTDIR)\bin\uic NewKey.ui -i NewKey.h -o NewKey.cpp \
	$(QTDIR)\bin\moc NewKey.h -o moc_NewKey.cpp \
	

"NewKey.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"NewKey.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"moc_NewKey.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

USERDEP__NEWKE="$(QTDIR)\bin\moc.exe"	"$(QTDIR)\bin\uic.exe"	
# Begin Custom Build - Uic'ing NewKey.ui...
InputPath=NewKey.ui

BuildCmds= \
	$(QTDIR)\bin\uic NewKey.ui -o NewKey.h \
	$(QTDIR)\bin\uic NewKey.ui -i NewKey.h -o NewKey.cpp \
	$(QTDIR)\bin\moc NewKey.h -o moc_NewKey.cpp \
	

"NewKey.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"NewKey.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"moc_NewKey.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=NewX509_UI.ui

!IF  "$(CFG)" == "xca - Win32 Release"

USERDEP__NEWX50="$(QTDIR)\bin\moc.exe"	"$(QTDIR)\bin\uic.exe"	
# Begin Custom Build - Uic'ing NewX509_UI.ui...
InputPath=NewX509_UI.ui

BuildCmds= \
	$(QTDIR)\bin\uic NewX509_UI.ui -o NewX509_UI.h \
	$(QTDIR)\bin\uic NewX509_UI.ui -i NewX509_UI.h -o NewX509_UI.cpp \
	$(QTDIR)\bin\moc NewX509_UI.h -o moc_NewX509_UI.cpp \
	

"NewX509_UI.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"NewX509_UI.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"moc_NewX509_UI.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

USERDEP__NEWX50="$(QTDIR)\bin\moc.exe"	"$(QTDIR)\bin\uic.exe"	
# Begin Custom Build - Uic'ing NewX509_UI.ui...
InputPath=NewX509_UI.ui

BuildCmds= \
	$(QTDIR)\bin\uic NewX509_UI.ui -o NewX509_UI.h \
	$(QTDIR)\bin\uic NewX509_UI.ui -i NewX509_UI.h -o NewX509_UI.cpp \
	$(QTDIR)\bin\moc NewX509_UI.h -o moc_NewX509_UI.cpp \
	

"NewX509_UI.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"NewX509_UI.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"moc_NewX509_UI.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=PassRead.ui

!IF  "$(CFG)" == "xca - Win32 Release"

USERDEP__PASSR="$(QTDIR)\bin\moc.exe"	"$(QTDIR)\bin\uic.exe"	
# Begin Custom Build - Uic'ing PassRead.ui...
InputPath=PassRead.ui

BuildCmds= \
	$(QTDIR)\bin\uic PassRead.ui -o PassRead.h \
	$(QTDIR)\bin\uic PassRead.ui -i PassRead.h -o PassRead.cpp \
	$(QTDIR)\bin\moc PassRead.h -o moc_PassRead.cpp \
	

"PassRead.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"PassRead.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"moc_PassRead.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

USERDEP__PASSR="$(QTDIR)\bin\moc.exe"	"$(QTDIR)\bin\uic.exe"	
# Begin Custom Build - Uic'ing PassRead.ui...
InputPath=PassRead.ui

BuildCmds= \
	$(QTDIR)\bin\uic PassRead.ui -o PassRead.h \
	$(QTDIR)\bin\uic PassRead.ui -i PassRead.h -o PassRead.cpp \
	$(QTDIR)\bin\moc PassRead.h -o moc_PassRead.cpp \
	

"PassRead.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"PassRead.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"moc_PassRead.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=PassWrite.ui

!IF  "$(CFG)" == "xca - Win32 Release"

USERDEP__PASSW="$(QTDIR)\bin\moc.exe"	"$(QTDIR)\bin\uic.exe"	
# Begin Custom Build - Uic'ing PassWrite.ui...
InputPath=PassWrite.ui

BuildCmds= \
	$(QTDIR)\bin\uic PassWrite.ui -o PassWrite.h \
	$(QTDIR)\bin\uic PassWrite.ui -i PassWrite.h -o PassWrite.cpp \
	$(QTDIR)\bin\moc PassWrite.h -o moc_PassWrite.cpp \
	

"PassWrite.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"PassWrite.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"moc_PassWrite.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

USERDEP__PASSW="$(QTDIR)\bin\moc.exe"	"$(QTDIR)\bin\uic.exe"	
# Begin Custom Build - Uic'ing PassWrite.ui...
InputPath=PassWrite.ui

BuildCmds= \
	$(QTDIR)\bin\uic PassWrite.ui -o PassWrite.h \
	$(QTDIR)\bin\uic PassWrite.ui -i PassWrite.h -o PassWrite.cpp \
	$(QTDIR)\bin\moc PassWrite.h -o moc_PassWrite.cpp \
	

"PassWrite.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"PassWrite.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"moc_PassWrite.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=ReqDetail.ui

!IF  "$(CFG)" == "xca - Win32 Release"

USERDEP__REQDE="$(QTDIR)\bin\moc.exe"	"$(QTDIR)\bin\uic.exe"	
# Begin Custom Build - Uic'ing ReqDetail.ui...
InputPath=ReqDetail.ui

BuildCmds= \
	$(QTDIR)\bin\uic ReqDetail.ui -o ReqDetail.h \
	$(QTDIR)\bin\uic ReqDetail.ui -i ReqDetail.h -o ReqDetail.cpp \
	$(QTDIR)\bin\moc ReqDetail.h -o moc_ReqDetail.cpp \
	

"ReqDetail.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"ReqDetail.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"moc_ReqDetail.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

USERDEP__REQDE="$(QTDIR)\bin\moc.exe"	"$(QTDIR)\bin\uic.exe"	
# Begin Custom Build - Uic'ing ReqDetail.ui...
InputPath=ReqDetail.ui

BuildCmds= \
	$(QTDIR)\bin\uic ReqDetail.ui -o ReqDetail.h \
	$(QTDIR)\bin\uic ReqDetail.ui -i ReqDetail.h -o ReqDetail.cpp \
	$(QTDIR)\bin\moc ReqDetail.h -o moc_ReqDetail.cpp \
	

"ReqDetail.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"ReqDetail.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"moc_ReqDetail.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=TrustState.ui

!IF  "$(CFG)" == "xca - Win32 Release"

USERDEP__TRUST="$(QTDIR)\bin\moc.exe"	"$(QTDIR)\bin\uic.exe"	
# Begin Custom Build - Uic'ing TrustState.ui...
InputPath=TrustState.ui

BuildCmds= \
	$(QTDIR)\bin\uic TrustState.ui -o TrustState.h \
	$(QTDIR)\bin\uic TrustState.ui -i TrustState.h -o TrustState.cpp \
	$(QTDIR)\bin\moc TrustState.h -o moc_TrustState.cpp \
	

"TrustState.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"TrustState.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"moc_TrustState.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "xca - Win32 Debug"

USERDEP__TRUST="$(QTDIR)\bin\moc.exe"	"$(QTDIR)\bin\uic.exe"	
# Begin Custom Build - Uic'ing TrustState.ui...
InputPath=TrustState.ui

BuildCmds= \
	$(QTDIR)\bin\uic TrustState.ui -o TrustState.h \
	$(QTDIR)\bin\uic TrustState.ui -i TrustState.h -o TrustState.cpp \
	$(QTDIR)\bin\moc TrustState.h -o moc_TrustState.cpp \
	

"TrustState.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"TrustState.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"moc_TrustState.cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# End Group
# Begin Group "Translations"

# PROP Default_Filter "ts"
# Begin Source File

SOURCE=xca_de.ts
# End Source File
# Begin Source File

SOURCE=xca_es.ts
# End Source File
# End Group
# Begin Group "Generated"

# PROP Default_Filter ""
# Begin Source File

SOURCE=CertDetail.cpp
# End Source File
# Begin Source File

SOURCE=CertDetail.h
# End Source File
# Begin Source File

SOURCE=ExportKey_UI.cpp
# End Source File
# Begin Source File

SOURCE=ExportKey_UI.h
# End Source File
# Begin Source File

SOURCE=KeyDetail.cpp
# End Source File
# Begin Source File

SOURCE=KeyDetail.h
# End Source File
# Begin Source File

SOURCE=MainWindow_UI.cpp
# End Source File
# Begin Source File

SOURCE=MainWindow_UI.h
# End Source File
# Begin Source File

SOURCE=moc_CertDetail.cpp
# End Source File
# Begin Source File

SOURCE=lib\moc_db_key.cpp
# End Source File
# Begin Source File

SOURCE=lib\moc_db_temp.cpp
# End Source File
# Begin Source File

SOURCE=lib\moc_db_x509.cpp
# End Source File
# Begin Source File

SOURCE=lib\moc_db_x509req.cpp
# End Source File
# Begin Source File

SOURCE=moc_ExportKey.cpp
# End Source File
# Begin Source File

SOURCE=moc_ExportKey_UI.cpp
# End Source File
# Begin Source File

SOURCE=moc_KeyDetail.cpp
# End Source File
# Begin Source File

SOURCE=moc_MainWindow.cpp
# End Source File
# Begin Source File

SOURCE=moc_MainWindow_UI.cpp
# End Source File
# Begin Source File

SOURCE=moc_NewKey.cpp
# End Source File
# Begin Source File

SOURCE=moc_NewX509.cpp
# End Source File
# Begin Source File

SOURCE=moc_NewX509_UI.cpp
# End Source File
# Begin Source File

SOURCE=moc_PassRead.cpp
# End Source File
# Begin Source File

SOURCE=moc_PassWrite.cpp
# End Source File
# Begin Source File

SOURCE=moc_ReqDetail.cpp
# End Source File
# Begin Source File

SOURCE=moc_TrustState.cpp
# End Source File
# Begin Source File

SOURCE=NewKey.cpp
# End Source File
# Begin Source File

SOURCE=NewKey.h
# End Source File
# Begin Source File

SOURCE=NewX509_UI.cpp
# End Source File
# Begin Source File

SOURCE=NewX509_UI.h
# End Source File
# Begin Source File

SOURCE=PassRead.cpp
# End Source File
# Begin Source File

SOURCE=PassRead.h
# End Source File
# Begin Source File

SOURCE=PassWrite.cpp
# End Source File
# Begin Source File

SOURCE=PassWrite.h
# End Source File
# Begin Source File

SOURCE=ReqDetail.cpp
# End Source File
# Begin Source File

SOURCE=ReqDetail.h
# End Source File
# Begin Source File

SOURCE=TrustState.cpp
# End Source File
# Begin Source File

SOURCE=TrustState.h
# End Source File
# End Group
# End Target
# End Project
